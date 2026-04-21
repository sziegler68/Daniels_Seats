"""
Fuzzer Dashboard Tab — LIN Bus Analyzer GUI

Displays fuzz controls, a real-time hit table showing Action IDs that
triggered Status ID changes, a live status monitor with before/after
data comparison, and a scrolling timestamped event log.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk
from datetime import datetime
from styles import *


class FuzzerTab(ttk.Frame):
    """Fuzzer Dashboard: payload injection and response monitoring."""

    def __init__(self, parent, serial_manager, sniffer_tab):
        super().__init__(parent, padding=PAD_SECTION)
        self.serial = serial_manager
        self.sniffer_tab = sniffer_tab
        self.hits = []   # List of hit data dicts

        self._build_ui()

    # ═════════════════════════════════════════════════════════════
    #  UI Construction
    # ═════════════════════════════════════════════════════════════

    def _build_ui(self):
        # Resizable vertical layout
        paned = ttk.Panedwindow(self, orient=VERTICAL)
        paned.pack(fill=BOTH, expand=True)

        # ── Fuzz Controls ─────────────────────────────────────────
        top_frame = ttk.Frame(paned, padding=5)
        paned.add(top_frame, weight=0)

        ctrl_lf = ttk.LabelFrame(
            top_frame, text="  FUZZ CONTROL  ",
        )
        ctrl_lf.pack(fill=X)
        ctrl_frame = ttk.Frame(ctrl_lf, padding=PAD_SECTION)
        ctrl_frame.pack(fill=BOTH, expand=True)

        btn_row = ttk.Frame(ctrl_frame)
        btn_row.pack(fill=X, pady=(0, PAD_WIDGET))

        self.btn_start = ttk.Button(
            btn_row, text="\u25B6  Start Fuzz", bootstyle="warning",
            command=self._on_start_fuzz, width=16,
        )
        self.btn_start.pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.btn_stop = ttk.Button(
            btn_row, text="\u23F9  Stop", bootstyle="danger",
            command=self._on_stop_fuzz, state=DISABLED, width=12,
        )
        self.btn_stop.pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.status_label = ttk.Label(
            ctrl_frame, text="Status: Idle",
            font=FONT_BODY, bootstyle="secondary",
        )
        self.status_label.pack(anchor=W)

        # ── Action ID Hits Table ──────────────────────────────────
        mid_frame = ttk.Frame(paned, padding=5)
        paned.add(mid_frame, weight=2)

        hits_lf = ttk.LabelFrame(
            mid_frame, text="  ACTION ID HITS  ",
        )
        hits_lf.pack(fill=BOTH, expand=True)
        hits_frame = ttk.Frame(hits_lf, padding=PAD_SECTION)
        hits_frame.pack(fill=BOTH, expand=True)

        columns = (
            "action_id", "dlc", "payload",
            "status_id", "before", "after",
        )
        self.hits_tree = ttk.Treeview(
            hits_frame, columns=columns, show="headings",
            bootstyle="warning", height=8,
        )

        self.hits_tree.heading("action_id",  text="Action ID",        anchor=W)
        self.hits_tree.heading("dlc",        text="DLC",              anchor=CENTER)
        self.hits_tree.heading("payload",    text="Payload",          anchor=W)
        self.hits_tree.heading("status_id",  text="Triggered Status", anchor=W)
        self.hits_tree.heading("before",     text="Before",           anchor=W)
        self.hits_tree.heading("after",      text="After",            anchor=W)

        self.hits_tree.column("action_id",  width=90,  minwidth=70)
        self.hits_tree.column("dlc",        width=50,  minwidth=40, anchor=CENTER)
        self.hits_tree.column("payload",    width=160, minwidth=100)
        self.hits_tree.column("status_id",  width=120, minwidth=80)
        self.hits_tree.column("before",     width=180, minwidth=100)
        self.hits_tree.column("after",      width=180, minwidth=100)

        hits_scroll = ttk.Scrollbar(
            hits_frame, orient=VERTICAL, command=self.hits_tree.yview,
        )
        self.hits_tree.configure(yscrollcommand=hits_scroll.set)

        self.hits_tree.pack(side=LEFT, fill=BOTH, expand=True)
        hits_scroll.pack(side=RIGHT, fill=Y)

        self.hits_tree.tag_configure("hit", foreground=COLOR_ACCENT_ORANGE)

        # ── Event Log ─────────────────────────────────────────────
        bot_frame = ttk.Frame(paned, padding=5)
        paned.add(bot_frame, weight=1)

        log_lf = ttk.LabelFrame(
            bot_frame, text="  EVENT LOG  ",
        )
        log_lf.pack(fill=BOTH, expand=True)
        log_frame = ttk.Frame(log_lf, padding=PAD_SECTION)
        log_frame.pack(fill=BOTH, expand=True)

        self.log_text = tk.Text(
            log_frame, wrap=WORD, font=FONT_MONO_SMALL,
            bg=COLOR_LOG_BG, fg=COLOR_TEXT_BRIGHT,
            insertbackground=COLOR_ACCENT_CYAN,
            selectbackground=COLOR_LOG_SELECT,
            relief=FLAT, height=8,
        )
        log_scroll = ttk.Scrollbar(
            log_frame, orient=VERTICAL, command=self.log_text.yview,
        )
        self.log_text.configure(yscrollcommand=log_scroll.set)

        self.log_text.pack(side=LEFT, fill=BOTH, expand=True)
        log_scroll.pack(side=RIGHT, fill=Y)

        # Log text colour tags
        self.log_text.tag_configure("timestamp", foreground=COLOR_TEXT_DIM)
        self.log_text.tag_configure("hit",       foreground=COLOR_ACCENT_ORANGE)
        self.log_text.tag_configure("sending",   foreground=COLOR_TEXT_DIM)
        self.log_text.tag_configure("info",      foreground=COLOR_ACCENT_CYAN)

    # ═════════════════════════════════════════════════════════════
    #  Button Handlers
    # ═════════════════════════════════════════════════════════════

    def _on_start_fuzz(self):
        if not self.serial.is_connected():
            return

        # Get known responsive IDs from sniffer to skip & monitor
        active_ids = self.sniffer_tab.get_active_ids()

        if not active_ids:
            self._log(
                "\u26A0 No Status IDs known. Run a Sniffer scan first "
                "for best results.",
                "hit",
            )

        skip_str = ",".join(active_ids)
        cmd = f"START_FUZZ:SKIP={skip_str}" if skip_str else "START_FUZZ"

        self.btn_start.configure(state=DISABLED)
        self.btn_stop.configure(state=NORMAL)
        self.status_label.configure(
            text="Status: Fuzzing...", bootstyle="warning",
        )

        self.serial.send_command(cmd)

    def _on_stop_fuzz(self):
        self.serial.send_command("STOP_FUZZ")
        self.btn_start.configure(state=NORMAL)
        self.btn_stop.configure(state=DISABLED)
        self.status_label.configure(
            text="Status: Stopped", bootstyle="secondary",
        )

    # ═════════════════════════════════════════════════════════════
    #  Event Log Helper
    # ═════════════════════════════════════════════════════════════

    def _log(self, text: str, tag: str = "info"):
        """Add a timestamped entry to the event log."""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.log_text.insert(END, f"[{ts}] ", "timestamp")
        self.log_text.insert(END, f"{text}\n", tag)
        self.log_text.see(END)

        # Cap at 5000 lines to prevent unbounded memory growth
        line_count = int(self.log_text.index("end-1c").split(".")[0])
        if line_count > 5000:
            self.log_text.delete("1.0", "1000.0")

    # ═════════════════════════════════════════════════════════════
    #  Message Handlers (called by MainApp dispatcher)
    # ═════════════════════════════════════════════════════════════

    def handle_fuzz_sending(self, params: dict):
        """Handle FUZZ_SENDING:ID=XX,DLC=N,DATA=XX_XX"""
        id_hex = params.get("ID", "??")
        dlc    = params.get("DLC", "?")
        data   = params.get("DATA", "").replace("_", " ")

        self.status_label.configure(
            text=f"Status: Fuzzing ID 0x{id_hex}, DLC={dlc}, Data={data}",
        )
        self._log(
            f"SEND \u2192 ID=0x{id_hex} DLC={dlc} DATA={data}", "sending",
        )

    def handle_fuzz_hit(self, params: dict):
        """Handle FUZZ_HIT:ACTION_ID=XX,DLC=N,DATA=...,STATUS_ID=YY,..."""
        action_id = params.get("ACTION_ID", "??")
        dlc       = params.get("DLC", "?")
        data      = params.get("DATA", "").replace("_", " ")
        status_id = params.get("STATUS_ID", "??")
        before    = params.get("BEFORE", "").replace("_", " ")
        after     = params.get("AFTER", "").replace("_", " ")

        row_data = (
            f"0x{action_id}", dlc, data,
            f"0x{status_id}", before, after,
        )
        self.hits.append({
            "action_id": action_id,
            "dlc":       dlc,
            "data":      params.get("DATA", ""),
            "status_id": status_id,
            "before":    before,
            "after":     after,
        })

        self.hits_tree.insert("", END, values=row_data, tags=("hit",))

        # Auto-scroll
        children = self.hits_tree.get_children()
        if children:
            self.hits_tree.see(children[-1])

        self._log(
            f"\U0001F4A5 HIT! Action 0x{action_id} DLC={dlc} [{data}] \u2192 "
            f"Status 0x{status_id} changed: [{before}] \u2192 [{after}]",
            "hit",
        )

    def handle_fuzz_done(self, params: dict):
        """Handle FUZZ_DONE"""
        self.btn_start.configure(state=NORMAL)
        self.btn_stop.configure(state=DISABLED)
        hit_count = len(self.hits)
        self.status_label.configure(
            text=f"Status: Complete \u2014 {hit_count} hits found",
            bootstyle="success",
        )
        self._log(f"Fuzz complete. {hit_count} hits found.", "info")

    # ═════════════════════════════════════════════════════════════
    #  Public Accessor
    # ═════════════════════════════════════════════════════════════

    def get_hits(self) -> list:
        """Return list of hit data dicts for the Manual tab."""
        return self.hits
