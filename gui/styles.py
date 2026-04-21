"""
Theme and style configuration for the LIN Bus Analyzer GUI.
Uses ttkbootstrap with the 'cyborg' dark theme for a premium look.
"""

import ttkbootstrap as ttk


# ─────────────────────────────────────────────────────────────────
#  Theme
# ─────────────────────────────────────────────────────────────────

THEME_NAME = "cyborg"


# ─────────────────────────────────────────────────────────────────
#  Fonts
# ─────────────────────────────────────────────────────────────────

FONT_MONO          = ("Consolas", 11)
FONT_MONO_SMALL    = ("Consolas", 9)
FONT_HEADING       = ("Segoe UI", 14, "bold")
FONT_SUBHEADING    = ("Segoe UI", 11, "bold")
FONT_BODY          = ("Segoe UI", 10)
FONT_SMALL         = ("Segoe UI", 9)
FONT_TITLE         = ("Segoe UI", 16, "bold")


# ─────────────────────────────────────────────────────────────────
#  Custom Colors (supplement the theme palette)
# ─────────────────────────────────────────────────────────────────

COLOR_BG_DARK       = "#1a1a2e"
COLOR_BG_CARD       = "#16213e"
COLOR_ACCENT_CYAN   = "#00d4ff"
COLOR_ACCENT_GREEN  = "#00ff7f"
COLOR_ACCENT_ORANGE = "#ffa500"
COLOR_ACCENT_RED    = "#ff4444"
COLOR_ACCENT_PURPLE = "#b388ff"
COLOR_TEXT_DIM      = "#6c757d"
COLOR_TEXT_BRIGHT   = "#e0e0e0"
COLOR_LOG_BG        = "#0d1117"
COLOR_LOG_SELECT    = "#264f78"

# Category colors (ID Mapper tab)
COLOR_CAT_HEATED    = "#ff8c00"     # dark orange
COLOR_CAT_COOLED    = "#00bcd4"     # teal / cyan
COLOR_CAT_LUMBAR    = "#4caf50"     # green
COLOR_CAT_MOTOR     = "#9c27b0"     # purple
COLOR_CAT_HEADREST  = "#e91e63"     # pink
COLOR_CAT_OTHER     = "#6c757d"     # dim grey
COLOR_CAT_UNKNOWN   = "#455a64"     # blue-grey

CATEGORY_COLORS = {
    "Heated Seat": COLOR_CAT_HEATED,
    "Cooled Seat": COLOR_CAT_COOLED,
    "Lumbar":      COLOR_CAT_LUMBAR,
    "Seat Motor":  COLOR_CAT_MOTOR,
    "Headrest":    COLOR_CAT_HEADREST,
    "Other":       COLOR_CAT_OTHER,
    "Unknown":     COLOR_CAT_UNKNOWN,
}


# ─────────────────────────────────────────────────────────────────
#  Treeview Tag Styles
# ─────────────────────────────────────────────────────────────────

TREEVIEW_TAGS = {
    "responsive": {"foreground": COLOR_ACCENT_GREEN},
    "hit":        {"foreground": COLOR_ACCENT_ORANGE},
    "changed":    {"foreground": COLOR_ACCENT_RED},
    "info":       {"foreground": COLOR_TEXT_DIM},
    "highlight":  {"foreground": COLOR_ACCENT_CYAN},
}


# ─────────────────────────────────────────────────────────────────
#  Window Dimensions
# ─────────────────────────────────────────────────────────────────

WINDOW_MIN_WIDTH    = 1000
WINDOW_MIN_HEIGHT   = 700
WINDOW_DEFAULT_SIZE = "1200x800"


# ─────────────────────────────────────────────────────────────────
#  Padding Constants
# ─────────────────────────────────────────────────────────────────

PAD_SECTION = 10
PAD_WIDGET  = 5
PAD_INNER   = 3


# ─────────────────────────────────────────────────────────────────
#  Custom Style Application
# ─────────────────────────────────────────────────────────────────

def apply_custom_styles(style):
    """Apply additional custom styles to the ttkbootstrap Style object."""

    # Treeview styling
    style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
    style.configure("Treeview", font=FONT_MONO, rowheight=28)

    # Custom label styles
    style.configure("Heading.TLabel",  font=FONT_HEADING)
    style.configure("Sub.TLabel",      font=FONT_SUBHEADING)
    style.configure("Mono.TLabel",     font=FONT_MONO)
    style.configure("Dim.TLabel",      font=FONT_SMALL,
                    foreground=COLOR_TEXT_DIM)

    # Custom button style for main actions
    style.configure("Action.TButton",  font=("Segoe UI", 10, "bold"))
