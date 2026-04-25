"""
Fuzzer Dashboard Tab — LIN Bus Analyzer GUI

Displays fuzz controls, a real-time hit table showing Action IDs that
triggered Status ID changes, a live status monitor with before/after
data comparison, and a scrolling timestamped event log.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import filedialog
import csv
import os
from datetime import datetime
from styles import *


class FuzzerTab(ttk.Frame):
    """Fuzzer Dashboard: payload injection and response monitoring."""

    def __init__(self, parent, serial_manager, sniffer_tab):
        super().__init__(parent, padding=PAD_SECTION)
        self.serial = serial_manager
        self.sniffer_tab = sniffer_tab
        self.hits = []   # List of hit data dicts
        self.aggregated_ids = {} # Hex ID -> List of filenames

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

        self.btn_recapture = ttk.Button(
            btn_row, text="\u27F2  Recapture Baseline",
            bootstyle="info-outline",
            command=self._on_recapture_baseline, width=22,
        )
        self.btn_recapture.pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.btn_resume = ttk.Button(
            btn_row, text="\u25B6  Resume Fuzz",
            bootstyle="success",
            command=self._on_resume_fuzz, width=16,
        )
        # Hidden by default — only shown when FUZZ_PAUSED fires
        self.btn_resume.pack_forget()

        self.status_label = ttk.Label(
            ctrl_frame, text="Status: Idle",
            font=FONT_BODY, bootstyle="secondary",
        )
        self.status_label.pack(anchor=W)

        self.status_label.pack(anchor=W)

        # ── Exclude List & Aggregation ────────────────────────────
        agg_frame_wrap = ttk.Frame(paned, padding=5)
        paned.add(agg_frame_wrap, weight=0)

        agg_lf = ttk.LabelFrame(
            agg_frame_wrap, text="  EXCLUDE LIST & AGGREGATION  ",
        )
        agg_lf.pack(fill=X)
        agg_frame = ttk.Frame(agg_lf, padding=PAD_SECTION)
        agg_frame.pack(fill=BOTH, expand=True)

        agg_top = ttk.Frame(agg_frame)
        agg_top.pack(fill=X, pady=(0, PAD_WIDGET))

        ttk.Button(
            agg_top, text="\U0001F4C2 Import Status CSVs...",
            bootstyle="info",
            command=self._on_import_csvs,
        ).pack(side=LEFT, padx=(0, PAD_WIDGET))

        ttk.Button(
            agg_top, text="\u2716 Clear",
            bootstyle="danger-outline",
            command=self._on_clear_csvs,
        ).pack(side=LEFT, padx=(0, PAD_WIDGET))

        ttk.Label(
            agg_top, text="Manual Skip IDs (Hex, comma-separated):",
        ).pack(side=LEFT, padx=(PAD_SECTION, PAD_INNER))

        self.manual_skip_entry = ttk.Entry(agg_top, font=FONT_MONO, width=30)
        self.manual_skip_entry.pack(side=LEFT, fill=X, expand=True)

        agg_cols = ("id", "occurrences", "sources")
        self.agg_tree = ttk.Treeview(
            agg_frame, columns=agg_cols, show="headings",
            bootstyle="info", height=3,
        )
        self.agg_tree.heading("id", text="ID (Hex)", anchor=W)
        self.agg_tree.heading("occurrences", text="Total Occurrences", anchor=CENTER)
        self.agg_tree.heading("sources", text="Source Files", anchor=W)

        self.agg_tree.column("id", width=80, minwidth=60)
        self.agg_tree.column("occurrences", width=120, minwidth=100, anchor=CENTER)
        self.agg_tree.column("sources", width=300, minwidth=150)

        agg_scroll = ttk.Scrollbar(
            agg_frame, orient=VERTICAL, command=self.agg_tree.yview,
        )
        self.agg_tree.configure(yscrollcommand=agg_scroll.set)
        self.agg_tree.pack(side=LEFT, fill=BOTH, expand=True)
        agg_scroll.pack(side=RIGHT, fill=Y)

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
            "status_id", "before", "after", "amperage",
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
        self.hits_tree.heading("amperage",   text="Amps (A)",         anchor=CENTER)

        self.hits_tree.column("action_id",  width=90,  minwidth=70)
        self.hits_tree.column("dlc",        width=50,  minwidth=40, anchor=CENTER)
        self.hits_tree.column("payload",    width=160, minwidth=100)
        self.hits_tree.column("status_id",  width=120, minwidth=80)
        self.hits_tree.column("before",     width=160, minwidth=100)
        self.hits_tree.column("after",      width=160, minwidth=100)
        self.hits_tree.column("amperage",   width=90,  minwidth=60, anchor=CENTER)

        hits_scroll = ttk.Scrollbar(
            hits_frame, orient=VERTICAL, command=self.hits_tree.yview,
        )
        self.hits_tree.configure(yscrollcommand=hits_scroll.set)

        self.hits_tree.pack(side=LEFT, fill=BOTH, expand=True)
        hits_scroll.pack(side=RIGHT, fill=Y)

        self.hits_tree.tag_configure("hit", foreground=COLOR_ACCENT_ORANGE)
        self.hits_tree.tag_configure("amp_hit", foreground=COLOR_ACCENT_PURPLE)

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

        # 1. Get known responsive IDs from sniffer (Current Session)
        sniffer_ids = self.sniffer_tab.get_active_ids()

        # 2. Get aggregated IDs from imported CSVs
        agg_ids = list(self.aggregated_ids.keys())

        # 3. Get manual skip IDs
        manual_ids = []
        raw_manual = self.manual_skip_entry.get().strip()
        if raw_manual:
            for part in raw_manual.split(","):
                part = part.strip()
                if part:
                    # Ensure it looks like a hex string if they typed "1A" instead of "0x1A"
                    if not part.lower().startswith("0x"):
                        part = f"0x{part}"
                    manual_ids.append(part)

        # 4. Deduplicate all IDs into a set
        all_hex_ids = set(sniffer_ids + agg_ids + manual_ids)

        if not all_hex_ids:
            self._log(
                "\u26A0 No Status IDs known. Run a Sniffer scan or import CSVs "
                "for best results.",
                "hit",
            )

        # 5. Convert hex IDs to decimal strings for the Arduino parser
        dec_ids = []
        for hid in all_hex_ids:
            try:
                val = int(hid, 16)
                dec_ids.append(str(val))
            except ValueError:
                pass

        skip_str = ",".join(dec_ids)
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

    def _on_recapture_baseline(self):
        """Ask the Arduino to re-snapshot all Status IDs as the new baseline.

        Useful after clearing a latched ECU state (e.g. power-cycling the seat
        module) so the fuzzer compares against a clean reference.
        """
        if not self.serial.is_connected():
            return
        self.serial.send_command("RECAPTURE_BASELINE")
        self._log("Baseline recapture requested", "info")

    def _on_resume_fuzz(self):
        """Send RESUME_FUZZ to the Arduino after the user has power-cycled
        the seat module to clear a hard-latched state."""
        if not self.serial.is_connected():
            return
        self.serial.send_command("RESUME_FUZZ")
        self.btn_resume.pack_forget()
        self.status_label.configure(
            text="Status: Resuming...", bootstyle="info",
        )
        self._log("RESUME_FUZZ sent \u2014 fuzzer will continue", "info")

    def _on_import_csvs(self):
        filepaths = filedialog.askopenfilenames(
            title="Select Status ID CSVs to Import",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if not filepaths:
            return

        imported_count = 0
        for fp in filepaths:
            filename = os.path.basename(fp)
            try:
                with open(fp, mode='r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    # Check if 'ID' column exists
                    if not reader.fieldnames or "ID" not in reader.fieldnames:
                        self._log(f"Skipped {filename} (no 'ID' column found)", "hit")
                        continue

                    for row in reader:
                        id_hex = row.get("ID", "").strip()
                        if id_hex.startswith("0x"):
                            id_hex = id_hex.lower() # Normalize to lowercase hex
                            if id_hex not in self.aggregated_ids:
                                self.aggregated_ids[id_hex] = []
                            if filename not in self.aggregated_ids[id_hex]:
                                self.aggregated_ids[id_hex].append(filename)
                                imported_count += 1
            except Exception as e:
                self._log(f"Error reading {filename}: {e}", "hit")

        self._refresh_agg_tree()
        self._log(f"Imported {imported_count} new unique ID/source mappings.", "info")

    def _on_clear_csvs(self):
        self.aggregated_ids.clear()
        self._refresh_agg_tree()
        self._log("Aggregated exclude list cleared.", "info")

    def _refresh_agg_tree(self):
        self.agg_tree.delete(*self.agg_tree.get_children())
        for id_hex in sorted(self.aggregated_ids.keys()):
            sources = self.aggregated_ids[id_hex]
            self.agg_tree.insert("", END, values=(
                id_hex,
                len(sources),
                ", ".join(sources)
            ))

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
            f"0x{status_id}", before, after, "\u2014",
        )
        self.hits.append({
            "action_id": action_id,
            "dlc":       dlc,
            "data":      params.get("DATA", ""),
            "status_id": status_id,
            "before":    before,
            "after":     after,
            "amperage":  None,
            "source":    "lin",
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

    def handle_fuzz_hit_amp(self, params: dict):
        """Handle FUZZ_HIT_AMP:ACTION_ID=XX,DLC=N,DATA=...,AMP=X.XX

        Purple row — a current spike was detected by the INA260 sensor
        even though the LIN Status IDs may not have changed.
        """
        action_id = params.get("ACTION_ID", "??")
        dlc       = params.get("DLC", "?")
        data      = params.get("DATA", "").replace("_", " ")
        amp_str   = params.get("AMP", "?.??")

        row_data = (
            f"0x{action_id}", dlc, data,
            "\u2014", "\u2014", "\u2014", f"{amp_str} A",
        )
        self.hits.append({
            "action_id": action_id,
            "dlc":       dlc,
            "data":      params.get("DATA", ""),
            "status_id": None,
            "before":    None,
            "after":     None,
            "amperage":  amp_str,
            "source":    "amp",
        })

        self.hits_tree.insert("", END, values=row_data, tags=("amp_hit",))

        # Auto-scroll
        children = self.hits_tree.get_children()
        if children:
            self.hits_tree.see(children[-1])

        self._log(
            f"\u26A1 AMP HIT! Action 0x{action_id} DLC={dlc} [{data}] "
            f"\u2192 Current spike: {amp_str} A",
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

    def handle_fuzz_paused(self, params: dict):
        """Handle FUZZ_PAUSED:MANUAL_RESET_REQD,AMP=X.XX

        The Arduino has detected a hard-latched current state that did not
        clear after the zero-frame active kill.  Show a warning and the
        Resume button so the user can power-cycle and continue.
        """
        amp_str = params.get("AMP", "?.??")

        self.status_label.configure(
            text=f"\u26A0 PAUSED \u2014 Manual reset required ({amp_str} A still flowing)",
            bootstyle="warning",
        )

        # Show the Resume button
        self.btn_resume.pack(side=LEFT, padx=(0, PAD_WIDGET))

        self._log(
            f"\u26A0 HARD LATCH: Current still at {amp_str} A after zero-frame "
            f"kill. Power-cycle the bench supply, then click \u25B6 Resume.",
            "hit",
        )

    # ═════════════════════════════════════════════════════════════
    #  Public Accessor
    # ═════════════════════════════════════════════════════════════

    def get_hits(self) -> list:
        """Return list of hit data dicts for the Manual tab."""
        return self.hits
