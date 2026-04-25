"""
Manual Trigger & Decoding Tab — LIN Bus Analyzer GUI

Provides a list of successfully fuzzed Action IDs with one-click trigger
buttons, inline notes fields for documenting physical seat responses,
a custom frame sender, and an exportable function map.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import filedialog
from datetime import datetime
from styles import *
import json
import csv


class ManualTab(ttk.Frame):
    """Manual Trigger & Decoding: resend payloads and map functions."""

    def __init__(self, parent, serial_manager, fuzzer_tab):
        super().__init__(parent, padding=PAD_SECTION)
        self.serial = serial_manager
        self.fuzzer_tab = fuzzer_tab
        self.function_map = []   # List of {action_id, payload, function}
        self._hit_rows = []      # Internal refs to hit row widgets
        self._repeat_active_hit = None   # Currently repeating hit dict (or None)
        self._repeat_job = None          # Tkinter after() job ID
        self._custom_repeating = False   # Custom sender repeat state
        self._custom_repeat_job = None

        self._build_ui()

    # ═════════════════════════════════════════════════════════════
    #  UI Construction
    # ═════════════════════════════════════════════════════════════

    def _build_ui(self):
        paned = ttk.Panedwindow(self, orient=VERTICAL)
        paned.pack(fill=BOTH, expand=True)

        # ── Discovered Action IDs with Trigger Buttons ────────────
        top_frame = ttk.Frame(paned, padding=5)
        paned.add(top_frame, weight=2)

        hits_outer = ttk.LabelFrame(
            top_frame, text="  DISCOVERED ACTION IDs  ",
        )
        hits_outer.pack(fill=BOTH, expand=True)
        hits_lf = ttk.Frame(hits_outer, padding=PAD_SECTION)
        hits_lf.pack(fill=BOTH, expand=True)

        # Toolbar
        toolbar = ttk.Frame(hits_lf)
        toolbar.pack(fill=X, pady=(0, PAD_WIDGET))

        ttk.Button(
            toolbar, text="\u21BB Refresh from Fuzzer",
            bootstyle="success-outline",
            command=self._refresh_hits,
        ).pack(side=LEFT)

        ttk.Label(
            toolbar,
            text=("Click \u25B6 to resend a payload.  "
                  "Add notes in the Notes column."),
            font=FONT_SMALL, bootstyle="secondary",
        ).pack(side=RIGHT)

        # Scrollable container for hit rows
        self.hits_container = ttk.Frame(hits_lf)
        self.hits_container.pack(fill=BOTH, expand=True)

        self.canvas = tk.Canvas(
            self.hits_container, highlightthickness=0, bg="#1a1a2e",
        )
        self.v_scroll = ttk.Scrollbar(
            self.hits_container, orient=VERTICAL, command=self.canvas.yview,
        )
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda _: self.canvas.configure(
                scrollregion=self.canvas.bbox("all"),
            ),
        )

        self._canvas_window = self.canvas.create_window(
            (0, 0), window=self.scrollable_frame, anchor=NW,
        )
        self.canvas.configure(yscrollcommand=self.v_scroll.set)

        # Header row inside scrollable frame
        header = ttk.Frame(self.scrollable_frame)
        header.pack(fill=X, padx=2, pady=2)

        ttk.Label(header, text="Action ID",  font=FONT_SUBHEADING,
                  width=10).pack(side=LEFT, padx=3)
        ttk.Label(header, text="DLC",        font=FONT_SUBHEADING,
                  width=5).pack(side=LEFT, padx=3)
        ttk.Label(header, text="Payload",    font=FONT_SUBHEADING,
                  width=20).pack(side=LEFT, padx=3)
        ttk.Label(header, text="",           width=8
                  ).pack(side=LEFT, padx=3)
        ttk.Label(header, text="Physical Function Notes",
                  font=FONT_SUBHEADING
                  ).pack(side=LEFT, padx=3, fill=X, expand=True)

        ttk.Separator(
            self.scrollable_frame, orient=HORIZONTAL,
        ).pack(fill=X, padx=2, pady=2)

        self.canvas.pack(side=LEFT, fill=BOTH, expand=True)
        self.v_scroll.pack(side=RIGHT, fill=Y)

        # Mouse wheel scrolling
        self.canvas.bind("<Enter>",
                         lambda _: self.canvas.bind_all(
                             "<MouseWheel>", self._on_mousewheel))
        self.canvas.bind("<Leave>",
                         lambda _: self.canvas.unbind_all("<MouseWheel>"))

        # ── Custom Frame Sender ───────────────────────────────────
        mid_frame = ttk.Frame(paned, padding=5)
        paned.add(mid_frame, weight=0)

        custom_outer = ttk.LabelFrame(
            mid_frame, text="  CUSTOM FRAME SENDER  ",
        )
        custom_outer.pack(fill=X)
        custom_lf = ttk.Frame(custom_outer, padding=PAD_SECTION)
        custom_lf.pack(fill=BOTH, expand=True)

        custom_row = ttk.Frame(custom_lf)
        custom_row.pack(fill=X)

        ttk.Label(custom_row, text="ID:", font=FONT_BODY
                  ).pack(side=LEFT, padx=(0, 3))
        self.custom_id = ttk.Entry(custom_row, width=6, font=FONT_MONO)
        self.custom_id.pack(side=LEFT, padx=(0, PAD_WIDGET))
        self.custom_id.insert(0, "0x")

        ttk.Label(custom_row, text="DLC:", font=FONT_BODY
                  ).pack(side=LEFT, padx=(0, 3))
        self.custom_dlc = ttk.Entry(custom_row, width=4, font=FONT_MONO)
        self.custom_dlc.pack(side=LEFT, padx=(0, PAD_WIDGET))

        ttk.Label(custom_row, text="Data:", font=FONT_BODY
                  ).pack(side=LEFT, padx=(0, 3))
        self.custom_data = ttk.Entry(custom_row, width=30, font=FONT_MONO)
        self.custom_data.pack(
            side=LEFT, padx=(0, PAD_WIDGET), fill=X, expand=True,
        )

        self._placeholder = "e.g. FF 00 A3"
        self.custom_data.insert(0, self._placeholder)
        self.custom_data.configure(foreground=COLOR_TEXT_DIM)
        self.custom_data.bind("<FocusIn>", self._clear_placeholder)
        self.custom_data.bind("<FocusOut>", self._restore_placeholder)

        ttk.Button(
            custom_row, text="\u25B6 Send", bootstyle="primary",
            command=self._on_send_custom, width=10,
        ).pack(side=LEFT, padx=(PAD_WIDGET, 0))

        self.btn_custom_repeat = ttk.Button(
            custom_row, text="\U0001F501 Repeat", bootstyle="info-outline",
            command=self._on_toggle_custom_repeat, width=10,
        )
        self.btn_custom_repeat.pack(side=LEFT, padx=(PAD_INNER, 0))

        # ── Preset Test Frames ────────────────────────────────────
        preset_label_row = ttk.Frame(custom_lf)
        preset_label_row.pack(fill=X, pady=(PAD_WIDGET, 2))

        ttk.Label(
            preset_label_row,
            text="\U0001F9EA Scope Test Presets — click to auto-fill, then hit Send:",
            font=FONT_SMALL, bootstyle="info",
        ).pack(side=LEFT)

        preset_row = ttk.Frame(custom_lf)
        preset_row.pack(fill=X, pady=(0, PAD_WIDGET))

        # Define test presets:  (label, id_hex, dlc, data_str, tooltip)
        self._test_presets = [
            ("1-Byte Pulse",   "00", "1", "FF",
             "Simplest frame — single 0xFF byte. Easy to spot on scope."),
            ("Alternating",    "01", "4", "FF 00 FF 00",
             "Alternating high/low pattern — good for checking bit timing."),
            ("All Ones (8B)",  "02", "8", "FF FF FF FF FF FF FF FF",
             "Max-length all-high frame — longest waveform, easy to see."),
            ("All Zeros (8B)", "03", "8", "00 00 00 00 00 00 00 00",
             "Max-length all-low frame — compare with all-ones."),
            ("Staircase",      "04", "8", "01 02 04 08 10 20 40 80",
             "Walking bit pattern — each byte has one bit set."),
        ]

        for label, pid, dlc, data, tip in self._test_presets:
            btn = ttk.Button(
                preset_row, text=f"\U0001F9EA {label}",
                bootstyle="info-outline",
                command=lambda p=pid, d=dlc, dt=data:
                    self._fill_preset(p, d, dt),
            )
            btn.pack(side=LEFT, padx=(0, PAD_INNER))

        # ── Function Map ──────────────────────────────────────────
        bot_frame = ttk.Frame(paned, padding=5)
        paned.add(bot_frame, weight=1)

        map_outer = ttk.LabelFrame(
            bot_frame, text="  FUNCTION MAP  ",
        )
        map_outer.pack(fill=BOTH, expand=True)
        map_lf = ttk.Frame(map_outer, padding=PAD_SECTION)
        map_lf.pack(fill=BOTH, expand=True)

        columns = ("action_id", "payload", "function")
        self.map_tree = ttk.Treeview(
            map_lf, columns=columns, show="headings",
            bootstyle="success", height=6,
        )

        self.map_tree.heading("action_id", text="Action ID",         anchor=W)
        self.map_tree.heading("payload",   text="Payload",           anchor=W)
        self.map_tree.heading("function",  text="Physical Function", anchor=W)

        self.map_tree.column("action_id", width=100, minwidth=80)
        self.map_tree.column("payload",   width=200, minwidth=120)
        self.map_tree.column("function",  width=400, minwidth=200)

        map_scroll = ttk.Scrollbar(
            map_lf, orient=VERTICAL, command=self.map_tree.yview,
        )
        self.map_tree.configure(yscrollcommand=map_scroll.set)

        self.map_tree.pack(side=LEFT, fill=BOTH, expand=True)
        map_scroll.pack(side=RIGHT, fill=Y)

        # Export / Save row
        export_row = ttk.Frame(map_lf)
        export_row.pack(fill=X, pady=(PAD_WIDGET, 0))

        ttk.Button(
            export_row, text="\u2795 Save Notes to Map",
            bootstyle="success", command=self._save_all_notes_to_map,
            width=18,
        ).pack(side=LEFT)

        ttk.Button(
            export_row, text="\U0001F4CB Export JSON",
            bootstyle="success-outline",
            command=self._export_json, width=14,
        ).pack(side=RIGHT, padx=PAD_INNER)

        ttk.Button(
            export_row, text="\U0001F4CB Export CSV",
            bootstyle="success-outline",
            command=self._export_csv, width=14,
        ).pack(side=RIGHT, padx=PAD_INNER)

    # ═════════════════════════════════════════════════════════════
    #  Scrolling
    # ═════════════════════════════════════════════════════════════

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    # ═════════════════════════════════════════════════════════════
    #  Placeholder Text Helpers
    # ═════════════════════════════════════════════════════════════

    def _clear_placeholder(self, _event):
        if self.custom_data.get() == self._placeholder:
            self.custom_data.delete(0, END)
            self.custom_data.configure(foreground=COLOR_TEXT_BRIGHT)

    def _restore_placeholder(self, _event):
        if not self.custom_data.get().strip():
            self.custom_data.insert(0, self._placeholder)
            self.custom_data.configure(foreground=COLOR_TEXT_DIM)

    # ═════════════════════════════════════════════════════════════
    #  Preset Test Frame Fill
    # ═════════════════════════════════════════════════════════════

    def _fill_preset(self, id_hex: str, dlc: str, data: str):
        """Auto-fill the custom frame sender fields with a test preset."""
        self.custom_id.delete(0, END)
        self.custom_id.insert(0, f"0x{id_hex}")

        self.custom_dlc.delete(0, END)
        self.custom_dlc.insert(0, dlc)

        self.custom_data.delete(0, END)
        self.custom_data.insert(0, data)
        self.custom_data.configure(foreground=COLOR_TEXT_BRIGHT)

    # ═════════════════════════════════════════════════════════════
    #  Hit Row Management
    # ═════════════════════════════════════════════════════════════

    def _refresh_hits(self):
        """Reload hit rows from the fuzzer tab's results."""
        # Clear rows (skip the header row [0] and separator [1])
        children = self.scrollable_frame.winfo_children()
        for widget in children[2:]:
            widget.destroy()

        self._hit_rows = []

        hits = self.fuzzer_tab.get_hits()
        for i, hit in enumerate(hits):
            self._add_hit_row(i, hit)

    def _add_hit_row(self, idx: int, hit: dict):
        """Insert a single triggerable hit row into the scrollable list."""
        row = ttk.Frame(self.scrollable_frame)
        row.pack(fill=X, padx=2, pady=1)

        ttk.Label(
            row, text=f"0x{hit['action_id']}", font=FONT_MONO,
            bootstyle="warning", width=10,
        ).pack(side=LEFT, padx=3)

        ttk.Label(
            row, text=hit["dlc"], font=FONT_MONO, width=5,
        ).pack(side=LEFT, padx=3)

        data_display = hit["data"].replace("_", " ")
        ttk.Label(
            row, text=data_display, font=FONT_MONO, width=20,
        ).pack(side=LEFT, padx=3)

        ttk.Button(
            row, text="\u25B6 Send", bootstyle="warning-outline", width=8,
            command=lambda h=hit: self._on_trigger(h),
        ).pack(side=LEFT, padx=3)

        repeat_btn = ttk.Button(
            row, text="\U0001F501", bootstyle="info-outline", width=4,
            command=lambda h=hit: None,  # placeholder, set below
        )
        repeat_btn.pack(side=LEFT, padx=3)
        # Wire up the command after the button exists so the lambda
        # can reference the button widget for visual state changes
        repeat_btn.configure(
            command=lambda h=hit, b=repeat_btn: self._on_toggle_repeat(h, b),
        )

        note_entry = ttk.Entry(row, font=FONT_BODY)
        note_entry.pack(side=LEFT, padx=3, fill=X, expand=True)

        self._hit_rows.append({
            "hit":        hit,
            "note_entry": note_entry,
            "repeat_btn": repeat_btn,
        })

    # ═════════════════════════════════════════════════════════════
    #  Trigger & Send Actions
    # ═════════════════════════════════════════════════════════════

    def _on_trigger(self, hit: dict):
        """Resend a previously discovered fuzz payload."""
        if not self.serial.is_connected():
            return
        cmd = (
            f"SEND_FRAME:ID={hit['action_id']},"
            f"DLC={hit['dlc']},"
            f"DATA={hit['data']}"
        )
        self.serial.send_command(cmd)

    # ── Repeat Toggle (Hit Rows) ──────────────────────────────────

    def _on_toggle_repeat(self, hit: dict, btn: ttk.Button):
        """Toggle continuous re-sending of a hit payload."""
        if self._repeat_active_hit is hit:
            # Stop repeating
            self._stop_repeat()
            return

        # Stop any other active repeat first
        self._stop_repeat()

        # Start repeating this hit
        self._repeat_active_hit = hit
        btn.configure(text="\u23F9", bootstyle="danger")
        self._repeat_loop(hit, btn)

    def _repeat_loop(self, hit: dict, btn: ttk.Button):
        """Timer-driven loop: sends the frame every 200 ms."""
        if self._repeat_active_hit is not hit:
            return
        if not self.serial.is_connected():
            self._stop_repeat()
            return
        self._on_trigger(hit)
        self._repeat_job = self.after(200, lambda: self._repeat_loop(hit, btn))

    def _stop_repeat(self):
        """Cancel any active hit repeat."""
        if self._repeat_job is not None:
            self.after_cancel(self._repeat_job)
            self._repeat_job = None

        # Reset all repeat buttons to default appearance
        for row_data in self._hit_rows:
            row_data["repeat_btn"].configure(
                text="\U0001F501", bootstyle="info-outline",
            )
        self._repeat_active_hit = None

    # ── Repeat Toggle (Custom Sender) ─────────────────────────────

    def _on_toggle_custom_repeat(self):
        """Toggle continuous re-sending of the custom frame."""
        if self._custom_repeating:
            self._stop_custom_repeat()
        else:
            self._custom_repeating = True
            self.btn_custom_repeat.configure(
                text="\u23F9 Stop", bootstyle="danger",
            )
            self._custom_repeat_loop()

    def _custom_repeat_loop(self):
        """Timer-driven loop: sends the custom frame every 200 ms."""
        if not self._custom_repeating:
            return
        if not self.serial.is_connected():
            self._stop_custom_repeat()
            return
        self._on_send_custom()
        self._custom_repeat_job = self.after(
            200, self._custom_repeat_loop,
        )

    def _stop_custom_repeat(self):
        """Cancel the custom sender repeat."""
        self._custom_repeating = False
        if self._custom_repeat_job is not None:
            self.after_cancel(self._custom_repeat_job)
            self._custom_repeat_job = None
        self.btn_custom_repeat.configure(
            text="\U0001F501 Repeat", bootstyle="info-outline",
        )

    def _on_send_custom(self):
        """Send a user-defined custom frame."""
        if not self.serial.is_connected():
            return

        id_str   = self.custom_id.get().strip().replace("0x", "").replace("0X", "")
        dlc_str  = self.custom_dlc.get().strip()
        data_str = self.custom_data.get().strip()

        if (not id_str or not dlc_str or not data_str
                or data_str == self._placeholder):
            return

        # Normalise: "FF 00 A3" → "FF_00_A3"
        data_formatted = data_str.replace(" ", "_").upper()

        cmd = (
            f"SEND_FRAME:ID={id_str.upper()},"
            f"DLC={dlc_str},"
            f"DATA={data_formatted}"
        )
        self.serial.send_command(cmd)

    # ═════════════════════════════════════════════════════════════
    #  Function Map
    # ═════════════════════════════════════════════════════════════

    def _save_all_notes_to_map(self):
        """Transfer all non-empty notes into the function map table."""
        for row_data in self._hit_rows:
            note = row_data["note_entry"].get().strip()
            if note:
                hit   = row_data["hit"]
                entry = {
                    "action_id": f"0x{hit['action_id']}",
                    "payload":   hit["data"].replace("_", " "),
                    "function":  note,
                }

                # Avoid duplicates
                if entry not in self.function_map:
                    self.function_map.append(entry)
                    self.map_tree.insert("", END, values=(
                        entry["action_id"],
                        entry["payload"],
                        entry["function"],
                    ))

    def _export_csv(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Function Map",
        )
        if filepath:
            with open(filepath, "w", newline="") as f:
                writer = csv.DictWriter(
                    f, fieldnames=["action_id", "payload", "function"],
                )
                writer.writeheader()
                writer.writerows(self.function_map)

    def _export_json(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Function Map",
        )
        if filepath:
            with open(filepath, "w") as f:
                json.dump(
                    {
                        "description":
                            "LIN Bus Function Map — "
                            "Lexus IS350 Seat ECU",
                        "generated": datetime.now().isoformat(),
                        "commands":  self.function_map,
                    },
                    f, indent=2,
                )
