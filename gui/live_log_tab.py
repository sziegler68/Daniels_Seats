"""
Live Traffic Log Tab — LIN Bus Analyzer GUI

Provides a real-time rolling log of all Serial traffic between the PC and the Arduino.
Features robust filtering (master suppression, deduplication), CSV/TXT export,
and visual color coding to easily spot data payload changes.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import filedialog
from datetime import datetime
from styles import *


class LiveLogTab(ttk.Frame):
    """Live traffic monitor with robust filtering and color coding."""

    def __init__(self, parent, serial_manager):
        super().__init__(parent, padding=PAD_SECTION)
        self.serial = serial_manager
        
        # Deduplication tracking: Action ID / Status ID -> Last seen payload
        self._last_seen_data = {}  

        self._build_ui()

    # ═════════════════════════════════════════════════════════════
    #  UI Construction
    # ═════════════════════════════════════════════════════════════

    def _build_ui(self):
        # ── Toolbar ──────────────────────────────────────────────
        toolbar = ttk.Frame(self, padding=(0, 0, 0, PAD_WIDGET))
        toolbar.pack(fill=X)

        self.btn_clear = ttk.Button(
            toolbar, text="\u21BB Clear Log", bootstyle="secondary-outline",
            command=self._on_clear,
        )
        self.btn_clear.pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.btn_save = ttk.Button(
            toolbar, text="\U0001F4CB Save Log", bootstyle="info-outline",
            command=self._on_save,
        )
        self.btn_save.pack(side=LEFT, padx=(0, PAD_WIDGET))

        # Checkboxes (Filters)
        self.var_autoscroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            toolbar, text="Auto-Scroll", bootstyle="success-round-toggle",
            variable=self.var_autoscroll,
        ).pack(side=LEFT, padx=(PAD_SECTION, PAD_WIDGET))

        self.var_suppress = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            toolbar, text="Hide Master (Show ECU Only)", bootstyle="warning-round-toggle",
            variable=self.var_suppress,
        ).pack(side=LEFT, padx=(0, PAD_WIDGET))

        self.var_dedupe = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            toolbar, text="Show Changes Only", bootstyle="danger-round-toggle",
            variable=self.var_dedupe,
            command=self._on_dedupe_toggled,
        ).pack(side=LEFT, padx=(0, PAD_WIDGET))

        # ── Log Text Area ─────────────────────────────────────────
        log_frame = ttk.Frame(self)
        log_frame.pack(fill=BOTH, expand=True)

        self.log_text = tk.Text(
            log_frame, wrap=WORD, font=FONT_MONO,
            bg=COLOR_LOG_BG, fg=COLOR_TEXT_BRIGHT,
            insertbackground=COLOR_ACCENT_CYAN,
            selectbackground=COLOR_LOG_SELECT,
            relief=FLAT,
        )
        log_scroll = ttk.Scrollbar(
            log_frame, orient=VERTICAL, command=self.log_text.yview,
        )
        self.log_text.configure(yscrollcommand=log_scroll.set)

        self.log_text.pack(side=LEFT, fill=BOTH, expand=True)
        log_scroll.pack(side=RIGHT, fill=Y)

        # ── Text Tags (Visual Coding) ─────────────────────────────
        self.log_text.tag_configure("timestamp", foreground=COLOR_TEXT_DIM)
        self.log_text.tag_configure("tx_label", foreground=COLOR_ACCENT_CYAN)
        self.log_text.tag_configure("rx_label", foreground=COLOR_ACCENT_GREEN)
        
        # Message content tags
        self.log_text.tag_configure("msg_tx", foreground=COLOR_ACCENT_CYAN)
        self.log_text.tag_configure("msg_rx_repeated", foreground=COLOR_TEXT_DIM)        # Light gray for repeated
        self.log_text.tag_configure("msg_rx_new", foreground=COLOR_ACCENT_ORANGE, font=FONT_MONO) # Orange for changes
        self.log_text.tag_configure("msg_error", foreground=COLOR_ACCENT_RED)
        self.log_text.tag_configure("msg_info", foreground=COLOR_TEXT_BRIGHT)

    # ═════════════════════════════════════════════════════════════
    #  Button Handlers
    # ═════════════════════════════════════════════════════════════

    def _on_clear(self):
        """Clear the log view and reset deduplication memory."""
        self.log_text.delete("1.0", END)
        self._last_seen_data.clear()

    def _on_dedupe_toggled(self):
        """Reset deduplication dictionary when toggled on to start fresh."""
        if self.var_dedupe.get():
            self._last_seen_data.clear()

    def _on_save(self):
        """Export the current text log to a file."""
        content = self.log_text.get("1.0", END).strip()
        if not content:
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Live Traffic Log",
            initialfile="lin_traffic_log.txt",
        )
        if filepath:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)

    # ═════════════════════════════════════════════════════════════
    #  Message Handler
    # ═════════════════════════════════════════════════════════════

    def handle_message(self, msg):
        """Process incoming SerialMessage from the queue."""
        
        # 1. Evaluate "Hide Master" filter
        # The GUI/Arduino abstraction means we don't handle raw 0x55 (Sync).
        # Master commands = TX from GUI, or INFO/PROGRESS from Arduino.
        # Slave data = STATUS_FOUND, MONITOR_DATA, FUZZ_HIT.
        is_slave_data = msg.msg_type in ["STATUS_FOUND", "MONITOR_DATA", "FUZZ_HIT"]
        
        if self.var_suppress.get() and not is_slave_data:
            return  # Drop this message

        # 2. Extract Data for Deduplication / Visual Coding
        data_tag = "msg_info"
        
        if msg.direction == "TX":
            data_tag = "msg_tx"
            direction_label = "[TX] \u2192"
            color_label = "tx_label"
        else:
            direction_label = "[RX] \u2190"
            color_label = "rx_label"
            
            if msg.msg_type == "ERROR":
                data_tag = "msg_error"
            elif is_slave_data:
                # Extract ID and DATA from params to check for changes
                id_hex = msg.params.get("ID", "")
                
                # In FUZZ_HIT, the ID might be ACTION_ID or STATUS_ID
                if not id_hex and msg.msg_type == "FUZZ_HIT":
                    id_hex = msg.params.get("STATUS_ID", "")
                    
                data = msg.params.get("DATA", "")
                
                if id_hex:
                    mem_key = f"{msg.msg_type}:{id_hex}"
                    
                    if mem_key in self._last_seen_data and self._last_seen_data[mem_key] == data:
                        # Repeated Data
                        if self.var_dedupe.get():
                            return  # Hide entirely
                        data_tag = "msg_rx_repeated"
                    else:
                        # New Data
                        self._last_seen_data[mem_key] = data
                        data_tag = "msg_rx_new"

        # 3. Format and Insert
        # E.g., [15:30:12.123] [RX] <- STATUS_FOUND:ID=2A,DATA=00_FF
        ts = msg.timestamp.strftime("%H:%M:%S.%f")[:-3]
        
        self.log_text.insert(END, f"[{ts}] ", "timestamp")
        self.log_text.insert(END, f"{direction_label} ", color_label)
        self.log_text.insert(END, f"{msg.raw}\n", data_tag)

        # 4. Limit Buffer Size to 5000 lines
        line_count = int(self.log_text.index("end-1c").split(".")[0])
        if line_count > 5000:
            # Delete first 500 lines to free memory
            self.log_text.delete("1.0", "501.0")

        # 5. Auto-Scroll
        if self.var_autoscroll.get():
            self.log_text.see(END)
