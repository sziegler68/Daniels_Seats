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
import json
import os
from datetime import datetime
from styles import *

# Path to the persistent blacklist file (project root)
_BLACKLIST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "blacklist.json",
)


class FuzzerTab(ttk.Frame):
    """Fuzzer Dashboard: payload injection and response monitoring."""

    def __init__(self, parent, serial_manager, sniffer_tab):
        super().__init__(parent, padding=PAD_SECTION)
        self.serial = serial_manager
        self.sniffer_tab = sniffer_tab
        self.hits = []   # List of hit data dicts
        self.aggregated_ids = {} # { "0x15": ["20231012.csv", "20231013.csv"] }

        self._loop_hit_job = None
        self._loop_active = False

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

        self.btn_resume = ttk.Button(
            btn_row, text="\u25B6  Resume", bootstyle="success",
            command=self._on_resume_fuzz, state=DISABLED, width=12,
        )
        self.btn_resume.pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.btn_recapture = ttk.Button(
            btn_row, text="\u27F2  Recapture Baseline",
            bootstyle="info-outline",
            command=self._on_recapture_baseline, width=22,
        )
        self.btn_recapture.pack(side=LEFT, padx=(0, PAD_SECTION))

        # Pause-on-Hit toggle
        self.pause_on_hit_var = tk.BooleanVar(value=False)
        self.chk_pause_on_hit = ttk.Checkbutton(
            btn_row, text="Pause on Hit",
            variable=self.pause_on_hit_var, bootstyle="warning-round-toggle",
        )
        self.chk_pause_on_hit.pack(side=LEFT, padx=(0, PAD_WIDGET))

        # DLC Toggles
        ttk.Label(btn_row, text="DLCs:", font=FONT_SMALL).pack(side=LEFT, padx=(PAD_INNER, 2))
        
        self.dlc2_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(btn_row, text="2", variable=self.dlc2_var, bootstyle="info-square-toggle").pack(side=LEFT, padx=2)
        
        self.dlc4_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(btn_row, text="4", variable=self.dlc4_var, bootstyle="info-square-toggle").pack(side=LEFT, padx=2)
        
        self.dlc8_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(btn_row, text="8", variable=self.dlc8_var, bootstyle="info-square-toggle").pack(side=LEFT, padx=2)

        self.status_label = ttk.Label(
            ctrl_frame, text="Status: Idle",
            font=FONT_BODY, bootstyle="secondary",
        )
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

        # Hits toolbar row
        hits_toolbar = ttk.Frame(hits_frame)
        hits_toolbar.pack(fill=X, pady=(0, PAD_WIDGET))

        ttk.Button(
            hits_toolbar, text="\U0001F4BE Export Hits...",
            bootstyle="success-outline",
            command=self._on_export_hits,
        ).pack(side=LEFT, padx=(0, PAD_WIDGET))

        ttk.Button(
            hits_toolbar, text="\u2716 Clear Hits",
            bootstyle="danger-outline",
            command=self._on_clear_hits,
        ).pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.btn_loop_hit = ttk.Button(
            hits_toolbar, text="\U0001F501 Loop Selected Hit",
            bootstyle="warning",
            command=self._on_toggle_loop_hit,
            state=DISABLED,
        )
        self.btn_loop_hit.pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.hit_count_label = ttk.Label(
            hits_toolbar, text="Hits: 0", font=FONT_BODY,
        )
        self.hit_count_label.pack(side=RIGHT)

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

        self.hits_tree.bind("<<TreeviewSelect>>", self._on_hit_selected)

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

        # 1. Get known responsive IDs from sniffer (bare hex: "15", "2A")
        sniffer_ids = self.sniffer_tab.get_active_ids()

        # 2. Get aggregated IDs from imported CSVs (prefixed: "0x15", "0x2a")
        agg_ids = list(self.aggregated_ids.keys())

        # 3. Get manual skip IDs (user types hex, e.g. "1A" or "0x1A")
        manual_ids = []
        raw_manual = self.manual_skip_entry.get().strip()
        if raw_manual:
            for part in raw_manual.split(","):
                part = part.strip()
                if part:
                    if not part.lower().startswith("0x"):
                        part = f"0x{part}"
                    manual_ids.append(part)

        # 4. Normalize ALL IDs to integer values for reliable deduplication.
        #    Sniffer gives "15" (bare hex), CSVs give "0x15", manual gives "0x1A".
        #    Without normalizing, set({"15", "0x15"}) would not deduplicate.
        all_int_ids = set()
        for hid in (sniffer_ids + agg_ids + manual_ids):
            try:
                all_int_ids.add(int(hid, 16))
            except ValueError:
                pass

        if not all_int_ids:
            self._log(
                "\u26A0 No Status IDs known. Run a Sniffer scan or import CSVs "
                "for best results.",
                "hit",
            )

        # 5. Convert to decimal strings for the Arduino parser (base-10)
        skip_str = ",".join(str(v) for v in sorted(all_int_ids))
        
        # 6. Parse DLC selection
        dlcs = []
        if self.dlc2_var.get(): dlcs.append("2")
        if self.dlc4_var.get(): dlcs.append("4")
        if self.dlc8_var.get(): dlcs.append("8")
        dlc_str = ",".join(dlcs)

        # Ensure at least one DLC is selected
        if not dlc_str:
            self._log("\u26A0 No DLCs selected. Defaulting to 8.", "error")
            dlc_str = "8"

        cmd = f"START_FUZZ:DLC={dlc_str}"
        if skip_str:
            cmd += f";SKIP={skip_str}"

        self.btn_start.configure(state=DISABLED)
        self.btn_stop.configure(state=NORMAL)
        self.status_label.configure(
            text="Status: Fuzzing...", bootstyle="warning",
        )

        # Sync the payload blacklist to the Arduino
        self.serial.send_command("CLEAR_BLACKLIST")
        bl_count = 0
        for entry in self._load_blacklist():
            bl_id = entry.get("id", "").replace("0x", "")
            bl_dlc = entry.get("dlc", 0)
            bl_data = entry.get("data", "")
            if bl_id and bl_dlc and bl_data:
                self.serial.send_command(f"ADD_BLACKLIST:ID={bl_id},DLC={bl_dlc},DATA={bl_data}")
                bl_count += 1
        
        if bl_count > 0:
            self._log(f"Synced {bl_count} payload blacklist entries to Arduino", "info")

        self.serial.send_command(cmd)

    def _on_stop_fuzz(self):
        self.serial.send_command("STOP_FUZZ")
        self._stop_loop()
        self.btn_start.configure(state=NORMAL)
        self.btn_stop.configure(state=DISABLED)
        self.btn_resume.configure(state=DISABLED)
        self.status_label.configure(
            text="Status: Stopped", bootstyle="secondary",
        )

    def _on_resume_fuzz(self):
        """Resume a paused fuzz session."""
        self._stop_loop()
        self.serial.send_command("RESUME_FUZZ")
        self.btn_resume.configure(state=DISABLED)
        self.btn_stop.configure(state=NORMAL)
        self.status_label.configure(
            text="Status: Fuzzing...", bootstyle="warning",
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

    def _on_export_hits(self):
        """Export all hits to a CSV file."""
        if not self.hits:
            self._log("No hits to export.", "info")
            return

        filepath = filedialog.asksaveasfilename(
            title="Export Hits As...",
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            initialfile=f"fuzz_hits_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )
        if not filepath:
            return

        try:
            with open(filepath, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "action_id", "dlc", "data", "status_id",
                    "before", "after", "amperage", "source",
                ])
                writer.writeheader()
                for hit in self.hits:
                    writer.writerow(hit)
            self._log(f"Exported {len(self.hits)} hits to {os.path.basename(filepath)}", "info")
        except Exception as e:
            self._log(f"Export failed: {e}", "hit")

    def _on_clear_hits(self):
        """Clear all hits from the table and internal list."""
        self._stop_loop()
        self.hits.clear()
        self.hits_tree.delete(*self.hits_tree.get_children())
        self.hit_count_label.configure(text="Hits: 0")
        self._log("Hits cleared.", "info")
        self.btn_loop_hit.configure(state=DISABLED)

    def _on_hit_selected(self, event):
        """Enable the Loop button if a hit is selected and fuzzer is paused or stopped."""
        selected = self.hits_tree.selection()
        # Enable if something is selected AND we are not actively fuzzing
        if selected and str(self.btn_stop.cget("state")) != str(NORMAL):
            self.btn_loop_hit.configure(state=NORMAL)
        elif selected and str(self.btn_resume.cget("state")) == str(NORMAL):
            # Also allow if paused
            self.btn_loop_hit.configure(state=NORMAL)
        else:
            self.btn_loop_hit.configure(state=DISABLED)
            
    def _on_toggle_loop_hit(self):
        """Start or stop looping the selected hit."""
        if self._loop_active:
            self._stop_loop()
        else:
            self._start_loop()

    def _start_loop(self):
        selected = self.hits_tree.selection()
        if not selected:
            return
            
        item = self.hits_tree.item(selected[0])
        values = item["values"]
        if not values: return
        
        # values = ("action_id", "dlc", "payload", "status_id", ...)
        # action_id is like "0x07", payload is "00 00 00 00 B6 00 00 00"
        action_id = str(values[0]).replace("0x", "")
        dlc = str(values[1])
        payload = str(values[2]).replace(" ", "_")
        
        cmd = f"SEND_FRAME:ID={action_id},DLC={dlc},DATA={payload}"
        
        self._loop_active = True
        self.btn_loop_hit.configure(
            text="\U0001F6D1 Stop Loop",
            bootstyle="danger"
        )
        self._log(f"Started looping ID={action_id} DATA={payload}", "info")
        self._loop_iteration(cmd)

    def _loop_iteration(self, cmd):
        if not self._loop_active:
            return
            
        if self.serial.is_connected():
            self.serial.send_command(cmd)
            
        self._loop_hit_job = self.after(200, self._loop_iteration, cmd)

    def _stop_loop(self):
        if not self._loop_active:
            return
            
        self._loop_active = False
        if self._loop_hit_job:
            self.after_cancel(self._loop_hit_job)
            self._loop_hit_job = None
            
        self.btn_loop_hit.configure(
            text="\U0001F501 Loop Selected Hit",
            bootstyle="warning"
        )
        self._log("Stopped loop.", "info")

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
    #  Public Accessor
    # ═════════════════════════════════════════════════════════════

    def get_hits(self):
        """Return the list of hit dicts (used by Manual Trigger tab)."""
        return list(self.hits)

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

        self.hit_count_label.configure(text=f"Hits: {len(self.hits)}")

        self._log(
            f"\U0001F4A5 HIT! Action 0x{action_id} DLC={dlc} [{data}] \u2192 "
            f"Status 0x{status_id} changed: [{before}] \u2192 [{after}]",
            "hit",
        )

        # Pause-on-hit: send PAUSE_FUZZ if toggle is on
        if self.pause_on_hit_var.get():
            self.serial.send_command("PAUSE_FUZZ")

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

        self.hit_count_label.configure(text=f"Hits: {len(self.hits)}")

        self._log(
            f"\u26A1 AMP HIT! Action 0x{action_id} DLC={dlc} [{data}] "
            f"\u2192 Current spike: {amp_str} A",
            "hit",
        )

        # Pause-on-hit: send PAUSE_FUZZ if toggle is on
        if self.pause_on_hit_var.get():
            self.serial.send_command("PAUSE_FUZZ")

    def handle_fuzz_done(self, params: dict):
        """Handle FUZZ_DONE"""
        self.btn_start.configure(state=NORMAL)
        self.btn_stop.configure(state=DISABLED)
        self.btn_resume.configure(state=DISABLED)
        hit_count = len(self.hits)
        self.status_label.configure(
            text=f"Status: Complete \u2014 {hit_count} hits found",
            bootstyle="success",
        )
        self._log(f"Fuzz complete. {hit_count} hits found.", "info")

    def handle_fuzz_paused(self, params: dict):
        """Handle FUZZ_PAUSED — Arduino is waiting for RESUME_FUZZ."""
        self.btn_resume.configure(state=NORMAL)
        self.btn_stop.configure(state=NORMAL)
        self.status_label.configure(
            text="Status: PAUSED \u2014 examine hit, then Resume or Stop",
            bootstyle="info",
        )
        self._log("\u23F8 Fuzzer paused. Click Resume to continue.", "info")

    def handle_fuzz_resumed(self, params: dict):
        """Handle FUZZ_RESUMED — Arduino has resumed fuzzing."""
        self.btn_resume.configure(state=DISABLED)
        self.btn_stop.configure(state=NORMAL)
        self.status_label.configure(
            text="Status: Fuzzing...", bootstyle="warning",
        )
        self._log("\u25B6 Fuzzer resumed.", "info")

    def handle_fatal_lockup(self, params: dict):
        """Handle FATAL_LOCKUP:ID=XX,DLC=N,DATA=XX_XX,AMPS=X.XX

        The Arduino's cooldown loop timed out after 5 seconds.
        Show a recovery modal with 3 options.
        """
        lockup_id   = params.get("ID", "??")
        lockup_dlc  = params.get("DLC", "?")
        lockup_data = params.get("DATA", "")
        lockup_amps = params.get("AMPS", "?.??")

        self.btn_start.configure(state=NORMAL)
        self.btn_stop.configure(state=DISABLED)
        self.status_label.configure(
            text=f"\u26A0 FATAL LOCKUP \u2014 {lockup_amps} A on ID 0x{lockup_id}",
            bootstyle="danger",
        )
        self._log(
            f"\u26A0 FATAL LOCKUP: ID=0x{lockup_id} DLC={lockup_dlc} "
            f"DATA=[{lockup_data.replace('_', ' ')}] "
            f"AMPS={lockup_amps} A \u2014 fuzzer halted",
            "hit",
        )

        # ── Calculate the "Next Step" ────────────────────────────
        next_id_hex   = lockup_id
        next_data_str = lockup_data
        try:
            data_bytes = [int(b, 16) for b in lockup_data.split("_")]
            # Increment the last non-zero byte (the sweep byte)
            incremented = False
            for i in range(len(data_bytes) - 1, -1, -1):
                if data_bytes[i] > 0 or i == 0:
                    if data_bytes[i] < 0xFF:
                        data_bytes[i] += 1
                        incremented = True
                    else:
                        # Byte rolled over — move to next byte position
                        data_bytes[i] = 0
                        if i + 1 < len(data_bytes):
                            # Next byte position sweep starts at 0x01
                            data_bytes[i + 1] = 0x01
                            incremented = True
                        else:
                            # All positions exhausted → next ID
                            raw_id = int(lockup_id, 16)
                            if raw_id < 0x3B:
                                next_id_hex = f"{raw_id + 1:02X}"
                                data_bytes = [0] * len(data_bytes)
                                incremented = True
                    break
            next_data_str = "_".join(f"{b:02X}" for b in data_bytes)
        except (ValueError, IndexError):
            pass

        # ── Build the recovery modal ─────────────────────────────
        modal = tk.Toplevel(self)
        modal.title("\u26A0 FATAL LOCKUP \u2014 Recovery Options")
        modal.geometry("600x420")
        modal.resizable(False, False)
        modal.grab_set()     # Make modal
        modal.transient(self)

        # Info section
        info_frame = ttk.Frame(modal, padding=15)
        info_frame.pack(fill=X)

        ttk.Label(info_frame,
                  text="\u26A1 ECU Lockup Detected",
                  font=FONT_HEADING, bootstyle="danger",
                  ).pack(anchor=W, pady=(0, 10))

        details = (
            f"Action ID:  0x{lockup_id}\n"
            f"DLC:        {lockup_dlc}\n"
            f"Payload:    [{lockup_data.replace('_', ' ')}]\n"
            f"Current:    {lockup_amps} A (still flowing)\n"
            f"\n"
            f"Next Step:  ID=0x{next_id_hex}  DATA=[{next_data_str.replace('_', ' ')}]"
        )
        ttk.Label(info_frame, text=details,
                  font=FONT_MONO, justify=LEFT,
                  ).pack(anchor=W)

        # Separator
        ttk.Separator(modal).pack(fill=X, padx=15, pady=5)

        # Button section
        btn_frame = ttk.Frame(modal, padding=15)
        btn_frame.pack(fill=X)

        def _on_acknowledge():
            """Populate the manual skip entry with the next step info."""
            self.manual_skip_entry.delete(0, END)
            self.manual_skip_entry.insert(0, f"0x{lockup_id}")
            self.status_label.configure(
                text=f"Status: Resume from ID 0x{next_id_hex}, "
                     f"DATA=[{next_data_str.replace('_', ' ')}]",
                bootstyle="info",
            )
            self._log(
                f"\u2714 Acknowledged lockup. Next: ID=0x{next_id_hex} "
                f"DATA=[{next_data_str.replace('_', ' ')}]. "
                f"Power-cycle bench PSU, then click Start Fuzz.",
                "info",
            )
            modal.destroy()

        def _on_blacklist():
            """Append the offending payload to blacklist.json."""
            entry = {
                "id":   f"0x{lockup_id}",
                "dlc":  int(lockup_dlc) if lockup_dlc.isdigit() else 0,
                "data": lockup_data,
            }
            blacklist = self._load_blacklist()
            if entry not in blacklist:
                blacklist.append(entry)
                self._save_blacklist(blacklist)
            self._log(
                f"\u26D4 Blacklisted: ID=0x{lockup_id} DLC={lockup_dlc} "
                f"DATA=[{lockup_data.replace('_', ' ')}]",
                "hit",
            )
            self.status_label.configure(
                text=f"Status: Payload blacklisted. Power-cycle and restart.",
                bootstyle="warning",
            )
            modal.destroy()

        def _on_rebaseline():
            """Send SET_BASELINE and restart the fuzzer."""
            if self.serial.is_connected():
                self.serial.send_command("SET_BASELINE")
            self._log(
                f"\u27F2 Re-baselined INA260 to current draw level. "
                f"Restarting fuzzer...",
                "info",
            )
            self.status_label.configure(
                text="Status: Re-baselined \u2014 restarting...",
                bootstyle="info",
            )
            modal.destroy()
            # Wait for Arduino to fully stop and emit FUZZ_DONE
            # before sending a new START_FUZZ command
            self.after(500, self._on_start_fuzz)

        ttk.Button(
            btn_frame,
            text="\u2714  Acknowledge & Resume (Manual)",
            bootstyle="info", width=40,
            command=_on_acknowledge,
        ).pack(fill=X, pady=(0, 8))

        ttk.Button(
            btn_frame,
            text="\u26D4  Blacklist This Payload",
            bootstyle="warning", width=40,
            command=_on_blacklist,
        ).pack(fill=X, pady=(0, 8))

        ttk.Button(
            btn_frame,
            text="\u27F2  Re-Baseline & Continue",
            bootstyle="success", width=40,
            command=_on_rebaseline,
        ).pack(fill=X)

    # ═════════════════════════════════════════════════════════════
    #  Blacklist Persistence
    # ═════════════════════════════════════════════════════════════

    def _load_blacklist(self) -> list:
        """Load blacklist.json from the project root. Returns [] if missing."""
        try:
            with open(_BLACKLIST_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _save_blacklist(self, blacklist: list):
        """Write the blacklist to blacklist.json in the project root."""
        with open(_BLACKLIST_PATH, "w", encoding="utf-8") as f:
            json.dump(blacklist, f, indent=2)

    # ═════════════════════════════════════════════════════════════
    #  Public Accessor
    # ═════════════════════════════════════════════════════════════

    def get_hits(self) -> list:
        """Return list of hit data dicts for the Manual tab."""
        return self.hits

