"""
LIN Bus Analyzer — Main Application
═══════════════════════════════════════════════════════════════════
Reverse engineering tool for Lexus IS350 seat ECU LIN-Bus commands.

Provides a tabbed dark-mode GUI with:
  • Sniffer Dashboard  — full header scan with progress tracking
  • Fuzzer Dashboard   — automated payload injection with hit detection
  • Manual Trigger     — one-click resend and physical function mapping

Run:
    pip install -r requirements.txt
    python app.py
═══════════════════════════════════════════════════════════════════
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk
import sys

from serial_manager import SerialManager
from sniffer_tab import SnifferTab
from fuzzer_tab import FuzzerTab
from manual_tab import ManualTab
from demo_mode import DemoSimulator
from styles import *


class LinBusAnalyzer(ttk.Window):
    """Main application window."""

    def __init__(self):
        super().__init__(
            title="LIN Bus Analyzer \u2014 Lexus IS350 Seat ECU",
            themename=THEME_NAME,
            size=(1200, 800),
            minsize=(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT),
        )

        self.serial = SerialManager()
        self.demo = DemoSimulator(self.serial.data_queue)
        self._msg_count = 0
        self._demo_active = False

        apply_custom_styles(self.style)
        self._build_ui()
        self._start_polling()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ═════════════════════════════════════════════════════════════
    #  UI Construction
    # ═════════════════════════════════════════════════════════════

    def _build_ui(self):
        # ── Connection Bar (always visible) ───────────────────────
        conn_frame = ttk.Frame(self, padding=(PAD_SECTION, PAD_WIDGET))
        conn_frame.pack(fill=X)

        ttk.Label(
            conn_frame, text="\u26A1 LIN Bus Analyzer",
            font=FONT_TITLE, bootstyle="info",
        ).pack(side=LEFT, padx=(0, 20))

        ttk.Label(
            conn_frame, text="Port:", font=FONT_BODY,
        ).pack(side=LEFT, padx=(0, 3))

        self.port_combo = ttk.Combobox(
            conn_frame, width=25, state="readonly", font=FONT_BODY,
        )
        self.port_combo.pack(side=LEFT, padx=(0, PAD_WIDGET))

        ttk.Button(
            conn_frame, text="\u21BB", bootstyle="info-outline", width=3,
            command=self._refresh_ports,
        ).pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.btn_connect = ttk.Button(
            conn_frame, text="Connect", bootstyle="success",
            command=self._toggle_connection, width=12,
        )
        self.btn_connect.pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.conn_status = ttk.Label(
            conn_frame, text="\u25CF Disconnected",
            font=FONT_BODY, bootstyle="danger",
        )
        self.conn_status.pack(side=LEFT, padx=(PAD_WIDGET, 0))

        # ── Demo Mode Controls (right side) ───────────────────────
        demo_frame = ttk.Frame(conn_frame)
        demo_frame.pack(side=RIGHT)

        ttk.Label(
            demo_frame, text="No Arduino?",
            font=FONT_SMALL, bootstyle="secondary",
        ).pack(side=LEFT, padx=(0, 5))

        self.btn_demo_sniff = ttk.Button(
            demo_frame, text="\u25B6 Demo Sniff",
            bootstyle="info-outline",
            command=self._on_demo_sniff, width=13,
        )
        self.btn_demo_sniff.pack(side=LEFT, padx=2)

        self.btn_demo_fuzz = ttk.Button(
            demo_frame, text="\u25B6 Demo Fuzz",
            bootstyle="warning-outline",
            command=self._on_demo_fuzz, width=13,
        )
        self.btn_demo_fuzz.pack(side=LEFT, padx=2)

        ttk.Separator(self, orient=HORIZONTAL).pack(fill=X)

        # ── Notebook (tabbed interface) ───────────────────────────
        self.notebook = ttk.Notebook(self, bootstyle="info")
        self.notebook.pack(
            fill=BOTH, expand=True, padx=PAD_WIDGET, pady=PAD_WIDGET,
        )

        self.sniffer_tab = SnifferTab(self.notebook, self.serial)
        self.fuzzer_tab  = FuzzerTab(self.notebook, self.serial,
                                     self.sniffer_tab)
        self.manual_tab  = ManualTab(self.notebook, self.serial,
                                     self.fuzzer_tab)

        self.notebook.add(
            self.sniffer_tab, text="  \U0001F50D Sniffer Dashboard  ",
        )
        self.notebook.add(
            self.fuzzer_tab,  text="  \U0001F9EA Fuzzer Dashboard  ",
        )
        self.notebook.add(
            self.manual_tab,
            text="  \U0001F3AF Manual Trigger & Decode  ",
        )

        # ── Status Bar ────────────────────────────────────────────
        status_frame = ttk.Frame(
            self, padding=(PAD_SECTION, PAD_INNER),
        )
        status_frame.pack(fill=X, side=BOTTOM)

        self.status_text = ttk.Label(
            status_frame,
            text="Ready \u2014 Connect to Arduino to begin",
            font=FONT_SMALL, bootstyle="secondary",
        )
        self.status_text.pack(side=LEFT)

        self.msg_count_label = ttk.Label(
            status_frame, text="Messages: 0",
            font=FONT_SMALL, bootstyle="secondary",
        )
        self.msg_count_label.pack(side=RIGHT)

        # Initial port scan
        self._refresh_ports()

    # ═════════════════════════════════════════════════════════════
    #  Connection Management
    # ═════════════════════════════════════════════════════════════

    def _refresh_ports(self):
        """Refresh available COM ports in the dropdown."""
        ports = SerialManager.list_ports()
        self.port_combo["values"] = [desc for _, desc in ports]
        self._port_map = {desc: device for device, desc in ports}

        if ports:
            self.port_combo.current(0)

    def _toggle_connection(self):
        """Connect or disconnect."""
        if self.serial.is_connected():
            self.serial.disconnect()
            self.btn_connect.configure(text="Connect", bootstyle="success")
            self.conn_status.configure(
                text="\u25CF Disconnected", bootstyle="danger",
            )
            self.status_text.configure(text="Disconnected")
        else:
            selected = self.port_combo.get()
            if not selected or selected not in self._port_map:
                self.status_text.configure(text="Error: No port selected")
                return

            port = self._port_map[selected]
            if self.serial.connect(port):
                self.btn_connect.configure(
                    text="Disconnect", bootstyle="danger",
                )
                self.conn_status.configure(
                    text=f"\u25CF Connected ({port})", bootstyle="success",
                )
                self.status_text.configure(text=f"Connected to {port}")
            else:
                self.status_text.configure(
                    text=f"Error: Could not open {port}",
                )

    # ═════════════════════════════════════════════════════════════
    #  Serial Queue Polling
    # ═════════════════════════════════════════════════════════════

    def _start_polling(self):
        """Begin the serial data queue polling loop."""
        self._poll_serial()

    def _poll_serial(self):
        """Drain the queue and dispatch each message to the right tab."""
        try:
            while True:
                msg = self.serial.data_queue.get_nowait()
                self._dispatch_message(msg)
                self._msg_count += 1
                self.msg_count_label.configure(
                    text=f"Messages: {self._msg_count}",
                )
        except Exception:
            pass

        self.after(50, self._poll_serial)

    def _dispatch_message(self, msg):
        """Route a SerialMessage to the appropriate handler."""
        t = msg.msg_type
        p = msg.params

        # Sniffer messages
        if t == "SNIFF_PROGRESS":
            self.sniffer_tab.handle_sniff_progress(p)
        elif t == "STATUS_FOUND":
            self.sniffer_tab.handle_status_found(p)
        elif t == "SNIFF_DONE":
            self.sniffer_tab.handle_sniff_done(p)

        # Fuzzer messages
        elif t == "FUZZ_SENDING":
            self.fuzzer_tab.handle_fuzz_sending(p)
        elif t == "FUZZ_HIT":
            self.fuzzer_tab.handle_fuzz_hit(p)
        elif t == "FUZZ_DONE":
            self.fuzzer_tab.handle_fuzz_done(p)

        # General responses
        elif t == "PONG":
            self.status_text.configure(
                text="Arduino responded: PONG \u2713",
            )
        elif t == "INFO":
            self.status_text.configure(
                text=f"\u2139 {p.get('MSG', '')}",
            )
        elif t == "ERROR":
            self.status_text.configure(
                text=f"\u26A0 {p.get('MSG', '')}",
            )
        elif t == "FRAME_SENT":
            self.status_text.configure(
                text=f"Frame sent: ID=0x{p.get('ID', '??')}",
            )
        elif t == "MONITOR_DATA":
            pass   # Could be added to a live widget in a future update

    # ═════════════════════════════════════════════════════════════
    #  Shutdown
    # ═════════════════════════════════════════════════════════════

    def _on_close(self):
        """Clean shutdown: disconnect serial, stop demo, destroy window."""
        self.demo.stop()
        self.serial.disconnect()
        self.destroy()

    # ═════════════════════════════════════════════════════════════
    #  Demo Mode
    # ═════════════════════════════════════════════════════════════

    def _on_demo_sniff(self):
        """Run a simulated sniffer scan without any hardware."""
        if self.demo.is_running():
            self.demo.stop()
            return

        self._demo_active = True
        self.conn_status.configure(
            text="\u25CF DEMO MODE", bootstyle="warning",
        )
        self.status_text.configure(
            text="\u2139 Demo Mode — Simulating sniffer scan...",
        )
        self.sniffer_tab._on_clear()
        self.notebook.select(0)   # Switch to Sniffer tab
        self.demo.start_sniff_demo()

    def _on_demo_fuzz(self):
        """Run a simulated fuzz scan without any hardware."""
        if self.demo.is_running():
            self.demo.stop()
            return

        # If sniffer hasn't run, run it first
        if not self.sniffer_tab.results:
            self.status_text.configure(
                text="\u26A0 Run Demo Sniff first to discover Status IDs",
            )
            return

        self._demo_active = True
        self.conn_status.configure(
            text="\u25CF DEMO MODE", bootstyle="warning",
        )
        self.status_text.configure(
            text="\u2139 Demo Mode — Simulating fuzzer...",
        )
        self.notebook.select(1)   # Switch to Fuzzer tab
        self.demo.start_fuzz_demo()


# ─────────────────────────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────────────────────────

def main():
    app = LinBusAnalyzer()
    app.mainloop()


if __name__ == "__main__":
    main()
