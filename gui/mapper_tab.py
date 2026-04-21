"""
ID Mapper Tab — LIN Bus Analyzer GUI

Phase 3 of the reverse engineering workflow: after sniffing (Status IDs)
and fuzzing (Action IDs), this tab provides a structured process to:
  1. Test each discovered Action ID on the physical seat
  2. Classify its function (Heated Seat, Cooled Seat, Lumbar, etc.)
  3. Rank intensity levels within each category
  4. Link Status IDs (auto-populated from fuzzer data)
  5. Validate completeness and export the final mapping
  6. Write the finalised map to the Arduino controller
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import filedialog, messagebox
from dataclasses import dataclass, field, asdict
from datetime import datetime
from styles import *
import json
import csv


# ─────────────────────────────────────────────────────────────────
#  Data Model
# ─────────────────────────────────────────────────────────────────

CATEGORIES = [
    "Unknown", "Heated Seat", "Cooled Seat", "Lumbar",
    "Seat Motor", "Headrest", "Other",
]


@dataclass
class MappedID:
    """A single Action ID with its classified function metadata."""
    action_id:     str = ""       # hex, e.g. "12"
    dlc:           str = ""
    payload:       str = ""       # underscore-separated hex bytes
    category:      str = "Unknown"
    intensity_rank: int = 0       # 0 = unranked, 1-N within category
    notes:         str = ""
    status_id:     str = ""       # hex, auto-linked from fuzzer
    status_before: str = ""       # baseline status data
    status_after:  str = ""       # changed status data


class MapperTab(ttk.Frame):
    """ID Mapper: structured Action ID classification and controller export."""

    def __init__(self, parent, serial_manager, fuzzer_tab):
        super().__init__(parent, padding=PAD_SECTION)
        self.serial = serial_manager
        self.fuzzer_tab = fuzzer_tab
        self.mapped_ids: list[MappedID] = []
        self._row_widgets: list[dict] = []   # Widget refs for Panel 1 rows

        self._build_ui()

    # ═════════════════════════════════════════════════════════════
    #  UI Construction
    # ═════════════════════════════════════════════════════════════

    def _build_ui(self):
        paned = ttk.Panedwindow(self, orient=VERTICAL)
        paned.pack(fill=BOTH, expand=True)

        # ── Panel 1: Test & Classify ──────────────────────────────
        top_frame = ttk.Frame(paned, padding=5)
        paned.add(top_frame, weight=3)

        classify_lf = ttk.LabelFrame(
            top_frame, text="  TEST & CLASSIFY  ",
        )
        classify_lf.pack(fill=BOTH, expand=True)
        classify_inner = ttk.Frame(classify_lf, padding=PAD_SECTION)
        classify_inner.pack(fill=BOTH, expand=True)

        # Toolbar
        toolbar = ttk.Frame(classify_inner)
        toolbar.pack(fill=X, pady=(0, PAD_WIDGET))

        ttk.Button(
            toolbar, text="\u21BB Import Hits from Fuzzer",
            bootstyle="warning",
            command=self._import_hits,
        ).pack(side=LEFT, padx=(0, PAD_WIDGET))

        ttk.Button(
            toolbar, text="\U0001F4C2 Load Saved Map",
            bootstyle="info-outline",
            command=self._load_map,
        ).pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.import_status = ttk.Label(
            toolbar, text="No data loaded",
            font=FONT_SMALL, bootstyle="secondary",
        )
        self.import_status.pack(side=LEFT, padx=(PAD_WIDGET, 0))

        ttk.Label(
            toolbar,
            text=("Test each ID \u2192 pick Category \u2192 "
                  "add Notes \u2192 rank Intensity last"),
            font=FONT_SMALL, bootstyle="secondary",
        ).pack(side=RIGHT)

        # ── Scrollable row container ─────────────────────────────
        self.classify_container = ttk.Frame(classify_inner)
        self.classify_container.pack(fill=BOTH, expand=True)

        self.canvas = tk.Canvas(
            self.classify_container, highlightthickness=0,
            bg=COLOR_BG_DARK,
        )
        self.v_scroll = ttk.Scrollbar(
            self.classify_container, orient=VERTICAL,
            command=self.canvas.yview,
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

        # Resize canvas window width to fill available space
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        # Header row
        self._build_header_row()

        self.canvas.pack(side=LEFT, fill=BOTH, expand=True)
        self.v_scroll.pack(side=RIGHT, fill=Y)

        # Mouse wheel scrolling
        self.canvas.bind(
            "<Enter>",
            lambda _: self.canvas.bind_all(
                "<MouseWheel>", self._on_mousewheel),
        )
        self.canvas.bind(
            "<Leave>",
            lambda _: self.canvas.unbind_all("<MouseWheel>"),
        )

        # ── Panel 2: Category Summary ─────────────────────────────
        mid_frame = ttk.Frame(paned, padding=5)
        paned.add(mid_frame, weight=2)

        summary_lf = ttk.LabelFrame(
            mid_frame, text="  CATEGORY SUMMARY  ",
        )
        summary_lf.pack(fill=BOTH, expand=True)
        summary_inner = ttk.Frame(summary_lf, padding=PAD_SECTION)
        summary_inner.pack(fill=BOTH, expand=True)

        # Refresh button for summary
        sum_toolbar = ttk.Frame(summary_inner)
        sum_toolbar.pack(fill=X, pady=(0, PAD_WIDGET))

        ttk.Button(
            sum_toolbar, text="\u21BB Refresh Summary",
            bootstyle="info-outline",
            command=self._refresh_summary,
        ).pack(side=LEFT)

        self.summary_count = ttk.Label(
            sum_toolbar, text="",
            font=FONT_SMALL, bootstyle="secondary",
        )
        self.summary_count.pack(side=RIGHT)

        columns = (
            "category", "action_id", "payload",
            "rank", "status_id", "notes",
        )
        self.summary_tree = ttk.Treeview(
            summary_inner, columns=columns, show="headings",
            bootstyle="info", height=8,
        )

        self.summary_tree.heading("category",  text="Category",   anchor=W)
        self.summary_tree.heading("action_id", text="Action ID",  anchor=W)
        self.summary_tree.heading("payload",   text="Payload",    anchor=W)
        self.summary_tree.heading("rank",      text="Rank",       anchor=CENTER)
        self.summary_tree.heading("status_id", text="Status ID",  anchor=W)
        self.summary_tree.heading("notes",     text="Notes",      anchor=W)

        self.summary_tree.column("category",  width=120, minwidth=90)
        self.summary_tree.column("action_id", width=90,  minwidth=70)
        self.summary_tree.column("payload",   width=140, minwidth=100)
        self.summary_tree.column("rank",      width=60,  minwidth=40,
                                 anchor=CENTER)
        self.summary_tree.column("status_id", width=90,  minwidth=70)
        self.summary_tree.column("notes",     width=250, minwidth=120)

        sum_scroll = ttk.Scrollbar(
            summary_inner, orient=VERTICAL,
            command=self.summary_tree.yview,
        )
        self.summary_tree.configure(yscrollcommand=sum_scroll.set)

        self.summary_tree.pack(side=LEFT, fill=BOTH, expand=True)
        sum_scroll.pack(side=RIGHT, fill=Y)

        # Configure category tags for colour coding
        for cat_name, cat_color in CATEGORY_COLORS.items():
            tag = cat_name.lower().replace(" ", "_")
            self.summary_tree.tag_configure(tag, foreground=cat_color)

        # ── Panel 3: Save & Export ────────────────────────────────
        bot_frame = ttk.Frame(paned, padding=5)
        paned.add(bot_frame, weight=0)

        export_lf = ttk.LabelFrame(
            bot_frame, text="  SAVE & EXPORT  ",
        )
        export_lf.pack(fill=X)
        export_inner = ttk.Frame(export_lf, padding=PAD_SECTION)
        export_inner.pack(fill=BOTH, expand=True)

        btn_row = ttk.Frame(export_inner)
        btn_row.pack(fill=X)

        self.btn_save = ttk.Button(
            btn_row, text="\U0001F4BE  Save Data Points",
            bootstyle="success", width=20,
            command=self._on_save_data_points,
        )
        self.btn_save.pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.btn_write = ttk.Button(
            btn_row, text="\u26A1  Write IDs to Controller",
            bootstyle="warning", width=24,
            command=self._on_write_to_controller,
        )
        self.btn_write.pack(side=LEFT, padx=(0, PAD_WIDGET))

        ttk.Button(
            btn_row, text="\U0001F4CB Export JSON",
            bootstyle="success-outline", width=14,
            command=self._export_json,
        ).pack(side=RIGHT, padx=PAD_INNER)

        ttk.Button(
            btn_row, text="\U0001F4CB Export CSV",
            bootstyle="success-outline", width=14,
            command=self._export_csv,
        ).pack(side=RIGHT, padx=PAD_INNER)

        # Validation status
        self.validation_label = ttk.Label(
            export_inner, text="",
            font=FONT_BODY, wraplength=800,
        )
        self.validation_label.pack(fill=X, pady=(PAD_WIDGET, 0))

    # ═════════════════════════════════════════════════════════════
    #  Header Row
    # ═════════════════════════════════════════════════════════════

    def _build_header_row(self):
        """Build the column header inside the scrollable frame."""
        header = ttk.Frame(self.scrollable_frame)
        header.pack(fill=X, padx=2, pady=2)

        ttk.Label(header, text="#",          font=FONT_SUBHEADING,
                  width=4).pack(side=LEFT, padx=2)
        ttk.Label(header, text="Action ID",  font=FONT_SUBHEADING,
                  width=9).pack(side=LEFT, padx=2)
        ttk.Label(header, text="Payload",    font=FONT_SUBHEADING,
                  width=18).pack(side=LEFT, padx=2)
        ttk.Label(header, text="",           width=7
                  ).pack(side=LEFT, padx=2)
        ttk.Label(header, text="Category",   font=FONT_SUBHEADING,
                  width=13).pack(side=LEFT, padx=2)
        ttk.Label(header, text="Rank",       font=FONT_SUBHEADING,
                  width=5).pack(side=LEFT, padx=2)
        ttk.Label(header, text="Status ID",  font=FONT_SUBHEADING,
                  width=9).pack(side=LEFT, padx=2)
        ttk.Label(header, text="Notes",      font=FONT_SUBHEADING,
                  ).pack(side=LEFT, padx=2, fill=X, expand=True)

        ttk.Separator(
            self.scrollable_frame, orient=HORIZONTAL,
        ).pack(fill=X, padx=2, pady=2)

    # ═════════════════════════════════════════════════════════════
    #  Canvas Helpers
    # ═════════════════════════════════════════════════════════════

    def _on_canvas_configure(self, event):
        """Keep the scrollable frame width matching the canvas."""
        self.canvas.itemconfig(self._canvas_window, width=event.width)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    # ═════════════════════════════════════════════════════════════
    #  Import Hits from Fuzzer
    # ═════════════════════════════════════════════════════════════

    def _import_hits(self):
        """Pull discovered hits from the Fuzzer tab and populate rows."""
        hits = self.fuzzer_tab.get_hits()

        if not hits:
            self.import_status.configure(
                text="\u26A0 No hits found — run Fuzzer first",
                bootstyle="warning",
            )
            return

        # Clear existing rows (preserve header + separator)
        self._clear_rows()
        self.mapped_ids.clear()

        for i, hit in enumerate(hits):
            mapped = MappedID(
                action_id=hit.get("action_id", ""),
                dlc=hit.get("dlc", ""),
                payload=hit.get("data", ""),
                status_id=hit.get("status_id", ""),
                status_before=hit.get("before", ""),
                status_after=hit.get("after", ""),
            )
            self.mapped_ids.append(mapped)
            self._add_classify_row(i, mapped)

        self.import_status.configure(
            text=f"\u2713 Imported {len(hits)} Action IDs from Fuzzer",
            bootstyle="success",
        )

        # Auto-refresh summary
        self._refresh_summary()

    def _clear_rows(self):
        """Remove all classification rows (keep header + separator)."""
        children = self.scrollable_frame.winfo_children()
        for widget in children[2:]:
            widget.destroy()
        self._row_widgets.clear()

    def _add_classify_row(self, idx: int, mapped: MappedID):
        """Add one interactive classification row."""
        row = ttk.Frame(self.scrollable_frame)
        row.pack(fill=X, padx=2, pady=1)

        # Row number
        ttk.Label(
            row, text=f"{idx + 1}", font=FONT_MONO,
            width=4, bootstyle="secondary",
        ).pack(side=LEFT, padx=2)

        # Action ID
        ttk.Label(
            row, text=f"0x{mapped.action_id}", font=FONT_MONO,
            bootstyle="warning", width=9,
        ).pack(side=LEFT, padx=2)

        # Payload
        data_display = mapped.payload.replace("_", " ")
        ttk.Label(
            row, text=data_display, font=FONT_MONO, width=18,
        ).pack(side=LEFT, padx=2)

        # Test button
        ttk.Button(
            row, text="\u25B6 Test", bootstyle="warning-outline", width=7,
            command=lambda m=mapped: self._on_test(m),
        ).pack(side=LEFT, padx=2)

        # Category dropdown
        cat_var = tk.StringVar(value=mapped.category)
        cat_combo = ttk.Combobox(
            row, textvariable=cat_var,
            values=CATEGORIES, state="readonly",
            width=13, font=FONT_BODY,
        )
        cat_combo.pack(side=LEFT, padx=2)
        cat_combo.bind(
            "<<ComboboxSelected>>",
            lambda _e, i=idx, v=cat_var: self._on_category_change(i, v),
        )

        # Intensity rank
        rank_var = tk.IntVar(value=mapped.intensity_rank)
        rank_spin = ttk.Spinbox(
            row, from_=0, to=20, textvariable=rank_var,
            width=5, font=FONT_MONO,
        )
        rank_spin.pack(side=LEFT, padx=2)
        rank_var.trace_add(
            "write",
            lambda *_a, i=idx, v=rank_var: self._on_rank_change(i, v),
        )

        # Status ID (auto-linked, read-only)
        status_text = f"0x{mapped.status_id}" if mapped.status_id else "—"
        ttk.Label(
            row, text=status_text, font=FONT_MONO,
            bootstyle="info", width=9,
        ).pack(side=LEFT, padx=2)

        # Notes
        note_entry = ttk.Entry(row, font=FONT_BODY)
        note_entry.pack(side=LEFT, padx=2, fill=X, expand=True)
        if mapped.notes:
            note_entry.insert(0, mapped.notes)
        note_entry.bind(
            "<FocusOut>",
            lambda _e, i=idx, w=note_entry: self._on_note_change(i, w),
        )

        self._row_widgets.append({
            "row_frame":  row,
            "cat_var":    cat_var,
            "rank_var":   rank_var,
            "note_entry": note_entry,
        })

    # ═════════════════════════════════════════════════════════════
    #  Row Event Handlers
    # ═════════════════════════════════════════════════════════════

    def _on_test(self, mapped: MappedID):
        """Send the Action ID frame to the seat ECU."""
        if not self.serial.is_connected():
            return
        cmd = (
            f"SEND_FRAME:ID={mapped.action_id},"
            f"DLC={mapped.dlc},"
            f"DATA={mapped.payload}"
        )
        self.serial.send_command(cmd)

    def _on_category_change(self, idx: int, var: tk.StringVar):
        """Update the MappedID when the user picks a category."""
        if idx < len(self.mapped_ids):
            self.mapped_ids[idx].category = var.get()

    def _on_rank_change(self, idx: int, var: tk.IntVar):
        """Update the MappedID when the user changes the rank."""
        try:
            val = var.get()
        except tk.TclError:
            val = 0
        if idx < len(self.mapped_ids):
            self.mapped_ids[idx].intensity_rank = val

    def _on_note_change(self, idx: int, entry: ttk.Entry):
        """Update the MappedID when the user edits notes."""
        if idx < len(self.mapped_ids):
            self.mapped_ids[idx].notes = entry.get().strip()

    # ═════════════════════════════════════════════════════════════
    #  Category Summary (Panel 2)
    # ═════════════════════════════════════════════════════════════

    def _refresh_summary(self):
        """Rebuild the category summary tree from current mapped data."""
        # Sync notes from entry widgets before refreshing
        self._sync_all_from_widgets()

        self.summary_tree.delete(*self.summary_tree.get_children())

        if not self.mapped_ids:
            self.summary_count.configure(text="No IDs loaded")
            return

        # Sort by category then rank
        sorted_ids = sorted(
            self.mapped_ids,
            key=lambda m: (
                CATEGORIES.index(m.category)
                if m.category in CATEGORIES else 99,
                m.intensity_rank,
            ),
        )

        classified = sum(
            1 for m in self.mapped_ids if m.category != "Unknown"
        )
        total = len(self.mapped_ids)
        self.summary_count.configure(
            text=f"Classified: {classified} / {total}",
        )

        for m in sorted_ids:
            tag = m.category.lower().replace(" ", "_")
            rank_display = str(m.intensity_rank) if m.intensity_rank > 0 else "—"
            status_display = f"0x{m.status_id}" if m.status_id else "—"
            payload_display = m.payload.replace("_", " ")

            self.summary_tree.insert(
                "", END,
                values=(
                    m.category,
                    f"0x{m.action_id}",
                    payload_display,
                    rank_display,
                    status_display,
                    m.notes,
                ),
                tags=(tag,),
            )

    def _sync_all_from_widgets(self):
        """Pull the latest values from all row widgets into mapped_ids."""
        for i, widgets in enumerate(self._row_widgets):
            if i >= len(self.mapped_ids):
                break
            self.mapped_ids[i].category = widgets["cat_var"].get()
            try:
                self.mapped_ids[i].intensity_rank = widgets["rank_var"].get()
            except tk.TclError:
                self.mapped_ids[i].intensity_rank = 0
            self.mapped_ids[i].notes = widgets["note_entry"].get().strip()

    # ═════════════════════════════════════════════════════════════
    #  Save Data Points (Validation)
    # ═════════════════════════════════════════════════════════════

    def _on_save_data_points(self):
        """Validate all mapped IDs and report status."""
        self._sync_all_from_widgets()

        if not self.mapped_ids:
            self.validation_label.configure(
                text="\u26A0 No data to save. Import hits first.",
                bootstyle="warning",
            )
            return

        issues = []
        unclassified = []
        unranked = {}    # category -> list of action_ids missing rank
        dup_ranks = {}   # category -> {rank: [action_ids]}

        for m in self.mapped_ids:
            # Check unclassified
            if m.category == "Unknown":
                unclassified.append(f"0x{m.action_id}")

            # Track ranking issues per category
            if m.category not in ("Unknown", "Other"):
                if m.intensity_rank == 0:
                    unranked.setdefault(m.category, []).append(
                        f"0x{m.action_id}"
                    )
                else:
                    dup_ranks.setdefault(m.category, {})
                    dup_ranks[m.category].setdefault(
                        m.intensity_rank, []
                    ).append(f"0x{m.action_id}")

        # Build issue report
        if unclassified:
            issues.append(
                f"Unclassified IDs ({len(unclassified)}): "
                f"{', '.join(unclassified)}"
            )

        for cat, ids in unranked.items():
            issues.append(
                f"{cat} — missing intensity rank: {', '.join(ids)}"
            )

        for cat, rank_map in dup_ranks.items():
            for rank, ids in rank_map.items():
                if len(ids) > 1:
                    issues.append(
                        f"{cat} — duplicate rank {rank}: "
                        f"{', '.join(ids)}"
                    )

        if not issues:
            # All good
            self.validation_label.configure(
                text=("\u2713 All Action IDs classified and ranked. "
                      "Data points saved successfully!"),
                bootstyle="success",
            )
            self._refresh_summary()
            return

        # Build a message with issues
        issue_text = "\n".join(f"  \u2022 {iss}" for iss in issues)
        msg = (
            f"Validation found {len(issues)} issue(s):\n\n"
            f"{issue_text}\n\n"
            "Do you want to:\n"
            "  Yes = Save anyway (skip issues)\n"
            "  No  = Go back and fix"
        )

        result = messagebox.askyesno(
            "Data Point Validation", msg,
            icon="warning",
        )

        if result:
            self.validation_label.configure(
                text=(f"\u2713 Data points saved with "
                      f"{len(issues)} warning(s)."),
                bootstyle="warning",
            )
            self._refresh_summary()
        else:
            self.validation_label.configure(
                text=f"\u26A0 {len(issues)} issue(s) to resolve.",
                bootstyle="danger",
            )

    # ═════════════════════════════════════════════════════════════
    #  Write to Controller
    # ═════════════════════════════════════════════════════════════

    def _on_write_to_controller(self):
        """Serialize the mapping and send to the Arduino."""
        self._sync_all_from_widgets()

        if not self.serial.is_connected():
            self.validation_label.configure(
                text="\u26A0 Not connected to Arduino.",
                bootstyle="danger",
            )
            return

        if not self.mapped_ids:
            self.validation_label.configure(
                text="\u26A0 No mapped IDs to write.",
                bootstyle="warning",
            )
            return

        # Filter to only classified IDs
        valid = [
            m for m in self.mapped_ids if m.category != "Unknown"
        ]

        if not valid:
            self.validation_label.configure(
                text="\u26A0 No classified IDs to write. "
                     "Classify at least one ID first.",
                bootstyle="warning",
            )
            return

        # Confirm
        result = messagebox.askyesno(
            "Write to Controller",
            f"This will send {len(valid)} mapped ID(s) to the "
            f"Arduino controller.\n\nProceed?",
        )
        if not result:
            return

        # Send header
        self.serial.send_command(f"WRITE_MAP:COUNT={len(valid)}")

        # Send each entry
        for i, m in enumerate(valid):
            cmd = (
                f"MAP_ENTRY:IDX={i},"
                f"ACTION_ID={m.action_id},"
                f"DLC={m.dlc},"
                f"DATA={m.payload},"
                f"CATEGORY={m.category.upper().replace(' ', '_')},"
                f"RANK={m.intensity_rank},"
                f"STATUS_ID={m.status_id}"
            )
            self.serial.send_command(cmd)

        self.validation_label.configure(
            text=(f"\u26A1 Sent {len(valid)} entries to controller. "
                  "Waiting for ACK..."),
            bootstyle="info",
        )

    def handle_map_ack(self, params: dict):
        """Handle MAP_ACK response from Arduino."""
        count = params.get("COUNT", "?")
        self.validation_label.configure(
            text=f"\u2713 Controller acknowledged {count} map entries!",
            bootstyle="success",
        )

    def handle_map_error(self, params: dict):
        """Handle MAP_ERROR response from Arduino."""
        msg = params.get("MSG", "Unknown error")
        self.validation_label.configure(
            text=f"\u26A0 Controller error: {msg}",
            bootstyle="danger",
        )

    # ═════════════════════════════════════════════════════════════
    #  Export JSON / CSV
    # ═════════════════════════════════════════════════════════════

    def _export_json(self):
        """Export the full mapping as a JSON file."""
        self._sync_all_from_widgets()

        if not self.mapped_ids:
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export ID Map",
            initialfile="lin_seat_map.json",
        )
        if filepath:
            export_data = {
                "description":
                    "LIN Bus ID Map — Lexus IS350 Seat ECU",
                "generated": datetime.now().isoformat(),
                "mappings": [asdict(m) for m in self.mapped_ids],
            }
            with open(filepath, "w") as f:
                json.dump(export_data, f, indent=2)

            self.validation_label.configure(
                text=f"\u2713 Exported {len(self.mapped_ids)} entries "
                     f"to JSON.",
                bootstyle="success",
            )

    def _export_csv(self):
        """Export the full mapping as a CSV file."""
        self._sync_all_from_widgets()

        if not self.mapped_ids:
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export ID Map",
            initialfile="lin_seat_map.csv",
        )
        if filepath:
            fieldnames = [
                "action_id", "dlc", "payload", "category",
                "intensity_rank", "notes", "status_id",
                "status_before", "status_after",
            ]
            with open(filepath, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows([asdict(m) for m in self.mapped_ids])

            self.validation_label.configure(
                text=f"\u2713 Exported {len(self.mapped_ids)} entries "
                     f"to CSV.",
                bootstyle="success",
            )

    # ═════════════════════════════════════════════════════════════
    #  Load Saved Map
    # ═════════════════════════════════════════════════════════════

    def _load_map(self):
        """Load a previously saved JSON map file."""
        filepath = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Load ID Map",
        )
        if not filepath:
            return

        try:
            with open(filepath) as f:
                data = json.load(f)

            mappings = data.get("mappings", [])
            if not mappings:
                self.import_status.configure(
                    text="\u26A0 No mappings found in file.",
                    bootstyle="warning",
                )
                return

            # Clear and repopulate
            self._clear_rows()
            self.mapped_ids.clear()

            for i, entry in enumerate(mappings):
                mapped = MappedID(
                    action_id=entry.get("action_id", ""),
                    dlc=entry.get("dlc", ""),
                    payload=entry.get("payload", ""),
                    category=entry.get("category", "Unknown"),
                    intensity_rank=entry.get("intensity_rank", 0),
                    notes=entry.get("notes", ""),
                    status_id=entry.get("status_id", ""),
                    status_before=entry.get("status_before", ""),
                    status_after=entry.get("status_after", ""),
                )
                self.mapped_ids.append(mapped)
                self._add_classify_row(i, mapped)

            # Restore widget values from loaded data
            for i, widgets in enumerate(self._row_widgets):
                if i >= len(self.mapped_ids):
                    break
                m = self.mapped_ids[i]
                widgets["cat_var"].set(m.category)
                widgets["rank_var"].set(m.intensity_rank)
                if m.notes:
                    widgets["note_entry"].delete(0, END)
                    widgets["note_entry"].insert(0, m.notes)

            self.import_status.configure(
                text=f"\u2713 Loaded {len(mappings)} entries from file.",
                bootstyle="success",
            )
            self._refresh_summary()

        except (json.JSONDecodeError, KeyError, OSError) as e:
            self.import_status.configure(
                text=f"\u26A0 Load error: {e}",
                bootstyle="danger",
            )
