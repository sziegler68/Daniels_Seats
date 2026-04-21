"""
Sniffer Dashboard Tab — LIN Bus Analyzer GUI

Displays the header scan controls, a real-time progress bar, responsive
ID counter, checksum mode toggle, and a results table showing each
discovered Status ID with its PID, DLC, and raw hex data.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import filedialog
from styles import *


class SnifferTab(ttk.Frame):
    """Sniffer Dashboard: full header scan control and results display."""

    def __init__(self, parent, serial_manager):
        super().__init__(parent, padding=PAD_SECTION)
        self.serial = serial_manager
        self.scan_progress = 0
        self.responsive_count = 0
        self.results = []   # List of (id_display, pid_hex, dlc, data) tuples

        self._build_ui()

    # ═════════════════════════════════════════════════════════════
    #  UI Construction
    # ═════════════════════════════════════════════════════════════

    def _build_ui(self):
        # ── Scan Controls ─────────────────────────────────────────
        ctrl_lf = ttk.LabelFrame(
            self, text="  HEADER SCAN CONTROL  ",
        )
        ctrl_lf.pack(fill=X, pady=(0, PAD_SECTION))
        ctrl_frame = ttk.Frame(ctrl_lf, padding=PAD_SECTION)
        ctrl_frame.pack(fill=BOTH, expand=True)

        # Button row
        btn_row = ttk.Frame(ctrl_frame)
        btn_row.pack(fill=X, pady=(0, PAD_WIDGET))

        self.btn_start = ttk.Button(
            btn_row, text="\u25B6  Start Scan", bootstyle="success",
            command=self._on_start_scan, width=16,
        )
        self.btn_start.pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.btn_stop = ttk.Button(
            btn_row, text="\u23F9  Stop", bootstyle="danger",
            command=self._on_stop_scan, state=DISABLED, width=12,
        )
        self.btn_stop.pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.btn_clear = ttk.Button(
            btn_row, text="\u21BB  Clear", bootstyle="secondary-outline",
            command=self._on_clear, width=12,
        )
        self.btn_clear.pack(side=LEFT, padx=(0, PAD_WIDGET))

        # Checksum mode toggle (right-aligned)
        cksum_frame = ttk.Frame(btn_row)
        cksum_frame.pack(side=RIGHT)

        ttk.Label(
            cksum_frame, text="Checksum:", font=FONT_BODY,
        ).pack(side=LEFT, padx=(0, 5))

        self.cksum_var = tk.StringVar(value="ENHANCED")
        ttk.Radiobutton(
            cksum_frame, text="Enhanced", variable=self.cksum_var,
            value="ENHANCED", bootstyle="info-toolbutton",
            command=self._on_cksum_change,
        ).pack(side=LEFT, padx=2)
        ttk.Radiobutton(
            cksum_frame, text="Classic", variable=self.cksum_var,
            value="CLASSIC", bootstyle="info-toolbutton",
            command=self._on_cksum_change,
        ).pack(side=LEFT, padx=2)

        # Progress bar row
        progress_frame = ttk.Frame(ctrl_frame)
        progress_frame.pack(fill=X, pady=(0, PAD_WIDGET))

        self.progress_label = ttk.Label(
            progress_frame, text="Progress: 0 / 64", font=FONT_BODY,
        )
        self.progress_label.pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.progress_bar = ttk.Progressbar(
            progress_frame, maximum=64, mode="determinate",
            bootstyle="info-striped", length=400,
        )
        self.progress_bar.pack(
            side=LEFT, fill=X, expand=True, padx=(0, PAD_WIDGET),
        )

        self.count_label = ttk.Label(
            progress_frame, text="Responsive IDs: 0",
            font=FONT_SUBHEADING, bootstyle="success",
        )
        self.count_label.pack(side=RIGHT)

        # Wake Bus button
        self.btn_wake = ttk.Button(
            ctrl_frame, text="\u26A1 Wake Bus", bootstyle="warning-outline",
            command=self._on_wake_bus, width=14,
        )
        self.btn_wake.pack(anchor=W)

        # ── Results Table ─────────────────────────────────────────
        results_lf = ttk.LabelFrame(
            self, text="  SCAN RESULTS  ",
        )
        results_lf.pack(fill=BOTH, expand=True)
        results_frame = ttk.Frame(results_lf, padding=PAD_SECTION)
        results_frame.pack(fill=BOTH, expand=True)

        tree_frame = ttk.Frame(results_frame)
        tree_frame.pack(fill=BOTH, expand=True)

        columns = ("id", "pid", "dlc", "data")
        self.tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings",
            bootstyle="info", height=15,
        )

        self.tree.heading("id",   text="ID (Hex)",        anchor=W)
        self.tree.heading("pid",  text="PID (Hex)",       anchor=W)
        self.tree.heading("dlc",  text="DLC",             anchor=CENTER)
        self.tree.heading("data", text="Raw Data (Hex)",  anchor=W)

        self.tree.column("id",   width=100, minwidth=80)
        self.tree.column("pid",  width=100, minwidth=80)
        self.tree.column("dlc",  width=60,  minwidth=50, anchor=CENTER)
        self.tree.column("data", width=400, minwidth=200)

        scrollbar = ttk.Scrollbar(
            tree_frame, orient=VERTICAL, command=self.tree.yview,
        )
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)

        # Row tag styling
        self.tree.tag_configure("responsive",
                                foreground=COLOR_ACCENT_GREEN)
        self.tree.tag_configure("even",
                                background="#1e2d3d")

        # Export button
        export_frame = ttk.Frame(results_frame)
        export_frame.pack(fill=X, pady=(PAD_WIDGET, 0))

        ttk.Button(
            export_frame, text="\U0001F4CB Export CSV",
            bootstyle="info-outline",
            command=self._on_export_csv, width=14,
        ).pack(side=RIGHT, padx=PAD_INNER)

    # ═════════════════════════════════════════════════════════════
    #  Button Handlers
    # ═════════════════════════════════════════════════════════════

    def _on_start_scan(self):
        if not self.serial.is_connected():
            return
        self._on_clear()
        self.btn_start.configure(state=DISABLED)
        self.btn_stop.configure(state=NORMAL)
        self.serial.send_command("START_SNIFF")

    def _on_stop_scan(self):
        self.serial.send_command("STOP_SNIFF")
        self.btn_start.configure(state=NORMAL)
        self.btn_stop.configure(state=DISABLED)

    def _on_clear(self):
        self.tree.delete(*self.tree.get_children())
        self.results.clear()
        self.scan_progress = 0
        self.responsive_count = 0
        self.progress_bar["value"] = 0
        self.progress_label.configure(text="Progress: 0 / 64")
        self.count_label.configure(text="Responsive IDs: 0")

    def _on_cksum_change(self):
        if self.serial.is_connected():
            self.serial.send_command(f"SET_CKSUM:{self.cksum_var.get()}")

    def _on_wake_bus(self):
        if self.serial.is_connected():
            self.serial.send_command("WAKE_BUS")

    def _on_export_csv(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Scan Results",
        )
        if filepath:
            with open(filepath, "w") as f:
                f.write("ID,PID,DLC,Data\n")
                for row in self.results:
                    f.write(f"{row[0]},{row[1]},{row[2]},{row[3]}\n")

    # ═════════════════════════════════════════════════════════════
    #  Utility
    # ═════════════════════════════════════════════════════════════

    def _calc_pid_hex(self, id_hex: str) -> str:
        """Calculate the Protected ID from a raw hex ID string."""
        raw_id = int(id_hex, 16)
        p0 = (
            (raw_id >> 0) ^ (raw_id >> 1) ^ (raw_id >> 2) ^ (raw_id >> 4)
        ) & 0x01
        p1 = (
            ~((raw_id >> 1) ^ (raw_id >> 3) ^ (raw_id >> 4) ^ (raw_id >> 5))
        ) & 0x01
        pid = raw_id | (p0 << 6) | (p1 << 7)
        return f"0x{pid:02X}"

    # ═════════════════════════════════════════════════════════════
    #  Message Handlers (called by MainApp dispatcher)
    # ═════════════════════════════════════════════════════════════

    def handle_sniff_progress(self, params: dict):
        """Handle SNIFF_PROGRESS:ID=XX,TOTAL=64"""
        try:
            id_hex = params.get("ID", "00")
            current = int(id_hex, 16) + 1
            self.scan_progress = current
            self.progress_bar["value"] = current
            self.progress_label.configure(text=f"Progress: {current} / 64")
        except (ValueError, KeyError):
            pass

    def handle_status_found(self, params: dict):
        """Handle STATUS_FOUND:ID=XX,DLC=N,DATA=XX_XX_..."""
        try:
            id_hex     = params.get("ID", "??")
            dlc        = params.get("DLC", "?")
            data       = params.get("DATA", "").replace("_", " ")
            pid_hex    = self._calc_pid_hex(id_hex)
            id_display = f"0x{id_hex}"

            self.responsive_count += 1
            self.count_label.configure(
                text=f"Responsive IDs: {self.responsive_count}",
            )

            row_data = (id_display, pid_hex, dlc, data)
            self.results.append(row_data)

            self.tree.insert(
                "", END, values=row_data, tags=("responsive",),
            )

            # Auto-scroll to newest entry
            children = self.tree.get_children()
            if children:
                self.tree.see(children[-1])
        except (ValueError, KeyError):
            pass

    def handle_sniff_done(self, params: dict):
        """Handle SNIFF_DONE:COUNT=N"""
        self.progress_bar["value"] = 64
        self.progress_label.configure(
            text="Progress: 64 / 64  \u2713  Complete",
        )
        self.btn_start.configure(state=NORMAL)
        self.btn_stop.configure(state=DISABLED)

    # ═════════════════════════════════════════════════════════════
    #  Public Accessor
    # ═════════════════════════════════════════════════════════════

    def get_active_ids(self) -> list:
        """Return list of active (responsive) ID hex strings (e.g. ['15','2A'])."""
        return [row[0].replace("0x", "") for row in self.results]
