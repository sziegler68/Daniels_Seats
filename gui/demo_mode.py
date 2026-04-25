"""
Demo Mode Simulator for the LIN Bus Analyzer GUI.

Generates realistic fake serial messages to demonstrate the full
sniffer → fuzzer → manual trigger workflow without any Arduino
hardware connected. Runs in a background thread and pushes
simulated SerialMessage objects onto the serial manager's data queue.
"""

import threading
import time
import random
from serial_manager import SerialMessage


# ─────────────────────────────────────────────────────────────────
#  Simulated Seat ECU Data (realistic Lexus IS350 seat responses)
# ─────────────────────────────────────────────────────────────────

# Fake responsive Status IDs with plausible seat ECU data
FAKE_STATUS_IDS = [
    {"id": "04", "dlc": 4, "data": "40_00_00_80"},
    {"id": "09", "dlc": 3, "data": "00_3C_FF"},
    {"id": "15", "dlc": 4, "data": "22_00_B4_01"},
    {"id": "1A", "dlc": 6, "data": "80_00_00_FF_00_40"},
    {"id": "21", "dlc": 2, "data": "0F_A0"},
    {"id": "2C", "dlc": 4, "data": "00_FF_00_12"},
    {"id": "33", "dlc": 8, "data": "10_20_30_40_50_60_70_80"},
]

# Fake fuzz hits (Action IDs that "triggered" status changes)
FAKE_FUZZ_HITS = [
    {
        "action_id": "0A", "dlc": 1, "data": "42",
        "status_id": "15", "before": "22_00_B4_01", "after": "22_01_B4_01",
    },
    {
        "action_id": "0A", "dlc": 1, "data": "84",
        "status_id": "15", "before": "22_01_B4_01", "after": "22_02_B4_01",
    },
    {
        "action_id": "12", "dlc": 2, "data": "01_FF",
        "status_id": "2C", "before": "00_FF_00_12", "after": "01_FF_00_12",
    },
    {
        "action_id": "36", "dlc": 2, "data": "03_C0",
        "status_id": "33", "before": "10_20_30_40_50_60_70_80",
        "after": "10_20_30_40_50_60_F0_80",
    },
    {
        "action_id": "1F", "dlc": 1, "data": "80",
        "status_id": "1A", "before": "80_00_00_FF_00_40",
        "after": "80_01_00_FF_00_40",
    },
    {
        "action_id": "27", "dlc": 2, "data": "03_C0",
        "status_id": "04", "before": "40_00_00_80", "after": "40_03_00_80",
    },
]

# Fake current-spike hits ("Silent Hits" caught by INA260)
FAKE_AMP_HITS = [
    {"action_id": "0E", "dlc": 1, "data": "FF", "amp": "3.85"},
    {"action_id": "17", "dlc": 2, "data": "01_80", "amp": "1.42"},
    {"action_id": "28", "dlc": 1, "data": "40", "amp": "4.71"},
]


class DemoSimulator:
    """
    Simulates Arduino serial output for GUI testing.

    Usage:
        sim = DemoSimulator(serial_manager.data_queue)
        sim.start_sniff_demo()     # Simulates a full header scan
        sim.start_fuzz_demo()      # Simulates fuzzing with hits
    """

    def __init__(self, data_queue):
        self.queue = data_queue
        self._thread = None
        self._running = False
        self._stop_requested = False

    def is_running(self):
        return self._running

    def stop(self):
        self._stop_requested = True
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._running = False

    # ── Sniff Demo ────────────────────────────────────────────────

    def start_sniff_demo(self):
        """Simulate a full 64-ID header scan with ~7 responsive IDs."""
        if self._running:
            return
        self._stop_requested = False
        self._thread = threading.Thread(
            target=self._sniff_loop, daemon=True,
        )
        self._thread.start()

    def _sniff_loop(self):
        self._running = True

        self._push("INFO", {"MSG": "[DEMO] Starting simulated header scan..."})
        time.sleep(0.3)

        responsive_idx = 0

        for scan_id in range(60):
            if self._stop_requested:
                self._push("INFO", {"MSG": "[DEMO] Sniff aborted"})
                break

            # Send progress
            id_hex = f"{scan_id:02X}"
            self._push("SNIFF_PROGRESS", {"ID": id_hex, "TOTAL": "60"})

            # Check if this ID is one of our fake responsive ones
            if responsive_idx < len(FAKE_STATUS_IDS):
                fake = FAKE_STATUS_IDS[responsive_idx]
                if int(fake["id"], 16) == scan_id:
                    # Simulate response delay
                    time.sleep(random.uniform(0.05, 0.15))
                    self._push("STATUS_FOUND", {
                        "ID":   fake["id"],
                        "DLC":  str(fake["dlc"]),
                        "DATA": fake["data"],
                    })
                    responsive_idx += 1

            # Simulate scan timing (~30ms per ID)
            time.sleep(0.03)

        self._push("SNIFF_DONE", {
            "COUNT": str(len(FAKE_STATUS_IDS)),
        })
        self._running = False

    # ── Fuzz Demo ─────────────────────────────────────────────────

    def start_fuzz_demo(self):
        """Simulate a fuzzing run with periodic hits."""
        if self._running:
            return
        self._stop_requested = False
        self._thread = threading.Thread(
            target=self._fuzz_loop, daemon=True,
        )
        self._thread.start()

    def _fuzz_loop(self):
        self._running = True

        self._push("INFO", {
            "MSG": "[DEMO] Starting simulated fuzz (53 action IDs, "
                   "7 status IDs, Full Byte Sweep)...",
        })
        time.sleep(0.5)

        hit_idx = 0
        amp_idx = 0
        action_ids = [
            i for i in range(60)
            if f"{i:02X}" not in [s["id"] for s in FAKE_STATUS_IDS]
        ]

        for i, action_id in enumerate(action_ids[:20]):
            # Simulate fuzzing ~20 IDs for the demo (not all 57)
            if self._stop_requested:
                self._push("INFO", {"MSG": "[DEMO] Fuzz aborted"})
                break

            id_hex = f"{action_id:02X}"

            self._push("INFO", {
                "MSG": f"[DEMO] Fuzzing ID 0x{id_hex} "
                       f"({i + 1}/20)...",
            })

            # Send 3–5 FUZZ_SENDING messages per ID
            for attempt in range(random.randint(3, 5)):
                if self._stop_requested:
                    break

                fake_data = f"{random.randint(0, 255):02X}"
                self._push("FUZZ_SENDING", {
                    "ID":   id_hex,
                    "DLC":  "1",
                    "DATA": fake_data,
                })
                time.sleep(0.02)

            # Occasionally produce a hit
            if hit_idx < len(FAKE_FUZZ_HITS):
                hit = FAKE_FUZZ_HITS[hit_idx]
                if int(hit["action_id"], 16) == action_id:
                    time.sleep(0.1)  # Dramatic pause
                    self._push("FUZZ_HIT", {
                        "ACTION_ID": hit["action_id"],
                        "DLC":       str(hit["dlc"]),
                        "DATA":      hit["data"],
                        "STATUS_ID": hit["status_id"],
                        "BEFORE":    hit["before"],
                        "AFTER":     hit["after"],
                    })
                    hit_idx += 1

            # Occasionally produce a current-spike hit (purple)
            if amp_idx < len(FAKE_AMP_HITS):
                amp = FAKE_AMP_HITS[amp_idx]
                if int(amp["action_id"], 16) == action_id:
                    time.sleep(0.1)
                    self._push("FUZZ_HIT_AMP", {
                        "ACTION_ID": amp["action_id"],
                        "DLC":       str(amp["dlc"]),
                        "DATA":      amp["data"],
                        "AMP":       amp["amp"],
                    })
                    amp_idx += 1

            time.sleep(0.15)

        total_hits = hit_idx + amp_idx
        self._push("FUZZ_DONE", {})
        self._push("INFO", {
            "MSG": f"[DEMO] Fuzz complete. "
                   f"{hit_idx} LIN hits + {amp_idx} AMP hits found.",
        })
        self._running = False

    # ── Helpers ───────────────────────────────────────────────────

    def _push(self, msg_type: str, params: dict):
        """Create and enqueue a simulated SerialMessage."""
        parts = [f"{k}={v}" for k, v in params.items()]
        raw = f"{msg_type}:{','.join(parts)}" if parts else msg_type

        self.queue.put(SerialMessage(
            msg_type=msg_type,
            params=params,
            raw=raw,
        ))
