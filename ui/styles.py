"""
AY Vault - UI Theme & Style Configuration
Configures dark slate cybersecurity theme for Tkinter and ttk widgets.
"""

import tkinter as tk
from tkinter import ttk
from config.settings import THEME


def configure_theme(root: tk.Tk) -> None:
    """Configures global ttk and tk styles for a sleek dark cybersecurity theme."""
    root.configure(bg=THEME["bg_dark"])

    style = ttk.Style()
    style.theme_use("clam")

    # Frame backgrounds
    style.configure("TFrame", background=THEME["bg_dark"])
    style.configure("Card.TFrame", background=THEME["bg_card"], relief="solid", borderwidth=1)
    style.configure("Surface.TFrame", background=THEME["bg_surface"])
    style.configure("Sidebar.TFrame", background=THEME["sidebar_bg"])

    # Labels
    style.configure(
        "TLabel",
        background=THEME["bg_dark"],
        foreground=THEME["text_primary"],
        font=("Segoe UI", 10),
    )
    style.configure(
        "Card.TLabel",
        background=THEME["bg_card"],
        foreground=THEME["text_primary"],
        font=("Segoe UI", 10),
    )
    style.configure(
        "CardTitle.TLabel",
        background=THEME["bg_card"],
        foreground=THEME["text_secondary"],
        font=("Segoe UI", 8, "bold"),
    )
    style.configure(
        "CardValue.TLabel",
        background=THEME["bg_card"],
        foreground=THEME["text_primary"],
        font=("Segoe UI", 20, "bold"),
    )
    style.configure(
        "HeaderTitle.TLabel",
        background=THEME["bg_dark"],
        foreground=THEME["text_primary"],
        font=("Segoe UI", 18, "bold"),
    )
    style.configure(
        "HeaderSub.TLabel",
        background=THEME["bg_dark"],
        foreground=THEME["text_secondary"],
        font=("Segoe UI", 10),
    )
    style.configure(
        "SidebarHeader.TLabel",
        background=THEME["sidebar_bg"],
        foreground=THEME["text_primary"],
        font=("Segoe UI", 12, "bold"),
    )

    # Buttons
    style.configure(
        "Primary.TButton",
        background=THEME["primary"],
        foreground="#ffffff",
        font=("Segoe UI", 10, "bold"),
        borderwidth=0,
        focuscolor="none",
        padding=(16, 8),
    )
    style.map(
        "Primary.TButton",
        background=[("active", THEME["primary_hover"]), ("disabled", THEME["bg_surface"])],
        foreground=[("disabled", THEME["text_muted"])],
    )

    style.configure(
        "Success.TButton",
        background=THEME["success"],
        foreground="#ffffff",
        font=("Segoe UI", 10, "bold"),
        borderwidth=0,
        padding=(16, 8),
    )
    style.map("Success.TButton", background=[("active", "#059669")])

    style.configure(
        "Danger.TButton",
        background=THEME["danger"],
        foreground="#ffffff",
        font=("Segoe UI", 10, "bold"),
        borderwidth=0,
        padding=(16, 8),
    )
    style.map("Danger.TButton", background=[("active", "#dc2626")])

    style.configure(
        "Outline.TButton",
        background=THEME["bg_card"],
        foreground=THEME["text_primary"],
        font=("Segoe UI", 9),
        borderwidth=1,
        padding=(12, 6),
    )
    style.map(
        "Outline.TButton",
        background=[("active", THEME["bg_surface"])],
        foreground=[("active", "#ffffff")],
    )

    style.configure(
        "Nav.TButton",
        background=THEME["sidebar_bg"],
        foreground=THEME["text_secondary"],
        font=("Segoe UI", 10),
        borderwidth=0,
        anchor="w",
        padding=(18, 10),
    )
    style.map(
        "Nav.TButton",
        background=[("active", THEME["sidebar_active"])],
        foreground=[("active", THEME["text_primary"])],
    )

    style.configure(
        "NavActive.TButton",
        background=THEME["sidebar_active"],
        foreground=THEME["accent_cyan"],
        font=("Segoe UI", 10, "bold"),
        borderwidth=0,
        anchor="w",
        padding=(18, 10),
    )

    # Entries & Comboboxes
    style.configure(
        "TEntry",
        fieldbackground=THEME["bg_input"],
        foreground=THEME["text_primary"],
        insertcolor=THEME["text_primary"],
        bordercolor=THEME["border"],
        padding=7,
    )
    style.configure(
        "TCombobox",
        fieldbackground=THEME["bg_input"],
        background=THEME["bg_surface"],
        foreground=THEME["text_primary"],
        arrowcolor=THEME["text_primary"],
        padding=6,
    )

    # Treeview (Data Tables)
    style.configure(
        "Treeview",
        background=THEME["bg_card"],
        fieldbackground=THEME["bg_card"],
        foreground=THEME["text_primary"],
        font=("Segoe UI", 9),
        rowheight=32,
        borderwidth=0,
    )
    style.configure(
        "Treeview.Heading",
        background=THEME["bg_surface"],
        foreground=THEME["text_primary"],
        font=("Segoe UI", 9, "bold"),
        relief="flat",
        padding=8,
    )
    style.map(
        "Treeview",
        background=[("selected", THEME["primary"])],
        foreground=[("selected", "#ffffff")],
    )
    style.map(
        "Treeview.Heading",
        background=[("active", THEME["sidebar_active"])],
    )

    # Notebook Tabs
    style.configure(
        "TNotebook",
        background=THEME["bg_dark"],
        borderwidth=0,
    )
    style.configure(
        "TNotebook.Tab",
        background=THEME["bg_surface"],
        foreground=THEME["text_secondary"],
        padding=(18, 8),
        font=("Segoe UI", 9, "bold"),
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", THEME["bg_card"])],
        foreground=[("selected", THEME["accent_cyan"])],
    )
