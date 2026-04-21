"""
Serial Port Manager for the LIN Bus Analyzer GUI.

Handles USB serial communication with the Arduino Nano Every in a
background thread.  Incoming data is parsed into SerialMessage objects
and placed on a thread-safe queue for the GUI's polling loop to consume.
"""

import serial
import serial.tools.list_ports
import threading
import queue
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────
#  Data Structure
# ─────────────────────────────────────────────────────────────────

@dataclass
class SerialMessage:
    """Parsed message from the Arduino."""
    msg_type:  str            # e.g. "STATUS_FOUND", "SNIFF_PROGRESS"
    params:    dict           # Parsed key-value pairs
    raw:       str            # Original line from serial
    timestamp: datetime = field(default_factory=datetime.now)


# ─────────────────────────────────────────────────────────────────
#  Serial Manager
# ─────────────────────────────────────────────────────────────────

class SerialManager:
    """
    Manages the USB serial connection to the Arduino.

    - Uses a background reader thread to avoid blocking the GUI.
    - Incoming lines are parsed and enqueued in `data_queue`.
    - Outgoing commands are sent with a thread lock for safety.
    """

    BAUD_RATE = 115200

    def __init__(self):
        self.port: Optional[serial.Serial] = None
        self.data_queue: queue.Queue = queue.Queue()
        self._reader_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()

    # ── Port Enumeration ──────────────────────────────────────────

    @staticmethod
    def list_ports() -> list:
        """
        List available COM ports.
        Returns a list of (device, description) tuples, sorted by name.
        """
        ports = serial.tools.list_ports.comports()
        return [
            (p.device, f"{p.device} - {p.description}")
            for p in sorted(ports)
        ]

    # ── Connection Management ─────────────────────────────────────

    def connect(self, port_name: str) -> bool:
        """
        Open a serial connection on the specified COM port.
        Returns True on success, False on failure.
        """
        try:
            self.disconnect()
            self.port = serial.Serial(
                port=port_name,
                baudrate=self.BAUD_RATE,
                timeout=0.1,
                write_timeout=1.0,
            )
            self._running = True
            self._reader_thread = threading.Thread(
                target=self._reader_loop,
                daemon=True,
                name="SerialReader",
            )
            self._reader_thread.start()
            return True

        except serial.SerialException as e:
            self.data_queue.put(SerialMessage(
                msg_type="ERROR",
                params={"MSG": str(e)},
                raw=f"ERROR:MSG={e}",
            ))
            return False

    def disconnect(self):
        """Close the serial port and stop the reader thread."""
        self._running = False
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=2.0)
        if self.port and self.port.is_open:
            try:
                self.port.close()
            except Exception:
                pass
        self.port = None

    def is_connected(self) -> bool:
        """Check if the serial port is open."""
        return self.port is not None and self.port.is_open

    # ── Command Sending ───────────────────────────────────────────

    def send_command(self, command: str):
        """
        Send an ASCII command to the Arduino (appends newline).
        Thread-safe via internal lock.
        """
        if not self.is_connected():
            return

        with self._lock:
            try:
                self.port.write(f"{command}\n".encode("ascii"))
                self.port.flush()
            except serial.SerialException as e:
                self.data_queue.put(SerialMessage(
                    msg_type="ERROR",
                    params={"MSG": f"Write error: {e}"},
                    raw=f"ERROR:MSG=Write error: {e}",
                ))

    # ── Background Reader Thread ──────────────────────────────────

    def _reader_loop(self):
        """Continuously read lines from serial and enqueue parsed messages."""
        while self._running and self.port and self.port.is_open:
            try:
                if self.port.in_waiting:
                    raw_line = (
                        self.port.readline()
                        .decode("ascii", errors="replace")
                        .strip()
                    )
                    if raw_line:
                        msg = self._parse_message(raw_line)
                        self.data_queue.put(msg)
                else:
                    time.sleep(0.01)   # Avoid busy-waiting

            except serial.SerialException:
                self.data_queue.put(SerialMessage(
                    msg_type="ERROR",
                    params={"MSG": "Serial connection lost"},
                    raw="ERROR:MSG=Serial connection lost",
                ))
                self._running = False
                break

            except Exception:
                time.sleep(0.01)

    # ── Message Parsing ───────────────────────────────────────────

    @staticmethod
    def _parse_message(raw: str) -> SerialMessage:
        """
        Parse a raw serial line into a SerialMessage.

        Expected format:  TYPE:KEY=VAL,KEY=VAL,...
        If no colon is present, the entire line is treated as the type.
        """
        params = {}

        if ":" in raw:
            msg_type, param_str = raw.split(":", 1)

            # Parse comma-separated key=value pairs
            parts = param_str.split(",")
            for part in parts:
                if "=" in part:
                    key, value = part.split("=", 1)
                    params[key.strip()] = value.strip()
        else:
            msg_type = raw.strip()

        return SerialMessage(
            msg_type=msg_type.strip(),
            params=params,
            raw=raw,
        )

    # ── Cleanup ───────────────────────────────────────────────────

    def __del__(self):
        self.disconnect()
