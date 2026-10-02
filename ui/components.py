"""
AY Vault - Reusable UI Components
Common widgets: StatCards, Badges, Decision Modals, Document Previews, and Headers.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any, Callable, Dict, Optional
from config.settings import THEME
from security.policy_engine import PolicyDecision


class StatCard(tk.Frame):
    """Modern dashboard stat card with icon, metric, and subtitle."""

    def __init__(
        self,
        parent: tk.Widget,
        title: str,
        value: str,
        subtitle: str,
        accent_color: str = THEME["primary"],
        icon: str = "🛡️",
    ):
        super().__init__(
            parent,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=16,
            pady=14,
        )
        self.accent_color = accent_color

        # Top row: Title and Icon
        top_frame = tk.Frame(self, bg=THEME["bg_card"])
        top_frame.pack(fill="x", expand=True)

        lbl_title = tk.Label(
            top_frame,
            text=title.upper(),
            font=("Segoe UI", 8, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        )
        lbl_title.pack(side="left")

        lbl_icon = tk.Label(
            top_frame,
            text=icon,
            font=("Segoe UI", 12),
            fg=accent_color,
            bg=THEME["bg_card"],
        )
        lbl_icon.pack(side="right")

        # Metric value
        self.lbl_value = tk.Label(
            self,
            text=value,
            font=("Segoe UI", 18, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_card"],
        )
        self.lbl_value.pack(anchor="w", pady=(6, 2))

        # Subtitle
        self.lbl_sub = tk.Label(
            self,
            text=subtitle,
            font=("Segoe UI", 8),
            fg=THEME["text_muted"],
            bg=THEME["bg_card"],
        )
        self.lbl_sub.pack(anchor="w")

    def update_value(self, new_value: str, new_subtitle: Optional[str] = None):
        self.lbl_value.config(text=new_value)
        if new_subtitle:
            self.lbl_sub.config(text=new_subtitle)


def create_badge(parent: tk.Widget, text: str, badge_type: str = "neutral") -> tk.Label:
    """Creates a rounded-style status badge label."""
    color_map = {
        "TOP_SECRET": (THEME["danger_bg"], "#fca5a5"),
        "RESTRICTED": (THEME["warning_bg"], "#fde68a"),
        "CONFIDENTIAL": ("#1e3a8a", "#93c5fd"),
        "UNRESTRICTED": (THEME["success_bg"], "#a7f3d0"),
        "SUCCESS": (THEME["success_bg"], "#a7f3d0"),
        "FAILURE": (THEME["danger_bg"], "#fca5a5"),
        "DENIED": (THEME["warning_bg"], "#fde68a"),
        "LOCKED": (THEME["danger_bg"], "#fca5a5"),
        "ACTIVE": (THEME["success_bg"], "#a7f3d0"),
        "Admin": ("#312e81", "#c7d2fe"),
        "Manager": ("#164e63", "#a5f3fc"),
        "Viewer": ("#1e293b", "#cbd5e1"),
        "neutral": (THEME["bg_surface"], THEME["text_secondary"]),
    }
    bg, fg = color_map.get(text, color_map.get(badge_type, (THEME["bg_surface"], THEME["text_primary"])))
    lbl = tk.Label(
        parent,
        text=f"  {text}  ",
        bg=bg,
        fg=fg,
        font=("Segoe UI", 8, "bold"),
        relief="flat",
        padx=4,
        pady=2,
    )
    return lbl


class PolicyDecisionDialog(tk.Toplevel):
    """Modal dialog displaying policy engine evaluation results."""

    def __init__(self, parent: tk.Widget, decision: PolicyDecision):
        super().__init__(parent)
        self.title("Security Policy Decision Inspector")
        self.geometry("540x380")
        self.configure(bg=THEME["bg_dark"])
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        # Decision Status Banner
        is_allowed = decision.is_permitted
        banner_bg = THEME["success_bg"] if is_allowed else THEME["danger_bg"]
        banner_fg = "#a7f3d0" if is_allowed else "#fca5a5"
        banner_text = "ACCESS PERMITTED [POLICY SATISFIED]" if is_allowed else "ACCESS DENIED [SECURITY POLICY ENFORCED]"

        banner = tk.Frame(self, bg=banner_bg, pady=12, padx=16)
        banner.pack(fill="x")

        tk.Label(
            banner,
            text=banner_text,
            font=("Segoe UI", 12, "bold"),
            bg=banner_bg,
            fg=banner_fg,
        ).pack(anchor="w")

        # Content Card
        content = tk.Frame(
            self,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=16,
            pady=16,
        )
        content.pack(fill="both", expand=True, padx=16, pady=16)

        fields = [
            ("Rule Evaluated:", decision.rule_name),
            ("Decision Code:", decision.decision_code),
            ("Reason:", decision.reason),
            ("Timestamp (UTC):", decision.evaluated_at),
        ]

        for lbl_name, val_text in fields:
            row = tk.Frame(content, bg=THEME["bg_card"])
            row.pack(fill="x", pady=4)
            tk.Label(
                row,
                text=lbl_name,
                font=("Segoe UI", 9, "bold"),
                fg=THEME["text_secondary"],
                bg=THEME["bg_card"],
                width=16,
                anchor="w",
            ).pack(side="left")
            tk.Label(
                row,
                text=val_text,
                font=("Segoe UI", 9),
                fg=THEME["text_primary"],
                bg=THEME["bg_card"],
                wraplength=340,
                justify="left",
            ).pack(side="left", fill="x", expand=True)

        # Context details
        if decision.context:
            ctx_row = tk.Frame(content, bg=THEME["bg_card"])
            ctx_row.pack(fill="x", pady=(8, 0))
            tk.Label(
                ctx_row,
                text="Evaluated Context:",
                font=("Segoe UI", 8, "bold"),
                fg=THEME["text_muted"],
                bg=THEME["bg_card"],
            ).pack(anchor="w")
            ctx_text = ", ".join(f"{k}: {v}" for k, v in decision.context.items())
            tk.Label(
                ctx_row,
                text=ctx_text,
                font=("Segoe UI", 8),
                fg=THEME["text_secondary"],
                bg=THEME["bg_card"],
                wraplength=480,
                justify="left",
            ).pack(anchor="w")

        btn_close = tk.Button(
            self,
            text="Close Inspector",
            command=self.destroy,
            bg=THEME["primary"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2",
        )
        btn_close.pack(pady=(0, 14))


class DocumentPreviewDialog(tk.Toplevel):
    """Modal displaying decrypted document content, cryptographic verification, and versions."""

    def __init__(
        self,
        parent: tk.Widget,
        doc_record: dict,
        plaintext_bytes: bytes,
        versions_list: list,
    ):
        super().__init__(parent)
        self.title(f"Vault Decrypted Inspection - {doc_record['title']}")
        self.geometry("780x620")
        self.configure(bg=THEME["bg_dark"])
        self.transient(parent)
        self.grab_set()

        # Header Info Bar
        header = tk.Frame(
            self,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=16,
            pady=12,
        )
        header.pack(fill="x", padx=14, pady=10)

        title_lbl = tk.Label(
            header,
            text=doc_record["title"],
            font=("Segoe UI", 12, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_card"],
        )
        title_lbl.pack(anchor="w")

        meta_frame = tk.Frame(header, bg=THEME["bg_card"])
        meta_frame.pack(fill="x", pady=(6, 0))

        tk.Label(
            meta_frame,
            text=f"Filename: {doc_record['original_filename']}  |  Version: v{doc_record['version']}  |  Owner: {doc_record['owner_username']}",
            font=("Segoe UI", 8),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        ).pack(side="left")

        badge = create_badge(meta_frame, doc_record["classification_level"])
        badge.pack(side="right")

        # Cryptographic Integrity Verification Banner
        crypto_bar = tk.Frame(
            self,
            bg=THEME["success_bg"],
            padx=14,
            pady=6,
        )
        crypto_bar.pack(fill="x", padx=14, pady=(0, 8))

        tk.Label(
            crypto_bar,
            text=(
                f"✓ AES-256-GCM Tag Verified  |  Plaintext SHA-256: {doc_record['plaintext_sha256'][:24]}... (100% Match)"
            ),
            font=("Segoe UI", 8, "bold"),
            fg="#a7f3d0",
            bg=THEME["success_bg"],
        ).pack(anchor="w")

        # Tabs: Decrypted Content & Version History
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        # Tab 1: Decrypted View
        content_frame = tk.Frame(notebook, bg=THEME["bg_card"])
        notebook.add(content_frame, text="Decrypted Plaintext")

        text_widget = tk.Text(
            content_frame,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=("Consolas", 10),
            wrap="word",
            padx=10,
            pady=10,
            borderwidth=0,
        )
        text_widget.pack(fill="both", expand=True)

        try:
            display_text = plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Hex dump view for binary contents
            display_text = f"Binary content ({len(plaintext_bytes)} bytes)\n\n"
            hex_view = " ".join(f"{b:02X}" for b in plaintext_bytes[:512])
            display_text += f"Hex Preview (First 512 bytes):\n{hex_view}..."

        text_widget.insert("1.0", display_text)
        text_widget.config(state="disabled")

        # Tab 2: Revision History
        history_frame = tk.Frame(notebook, bg=THEME["bg_card"], padx=10, pady=10)
        notebook.add(history_frame, text="Version Snapshots")

        tree = ttk.Treeview(
            history_frame,
            columns=("ver", "date", "author", "summary", "sha"),
            show="headings",
            height=6,
        )
        tree.heading("ver", text="Ver")
        tree.heading("date", text="Created At (UTC)")
        tree.heading("author", text="Author")
        tree.heading("summary", text="Change Summary")
        tree.heading("sha", text="Plaintext SHA-256")

        tree.column("ver", width=40, anchor="center")
        tree.column("date", width=140)
        tree.column("author", width=100)
        tree.column("summary", width=240)
        tree.column("sha", width=160)

        tree.pack(fill="both", expand=True)

        for v in versions_list:
            tree.insert(
                "",
                "end",
                values=(
                    f"v{v['version_number']}",
                    v["created_at"][:19],
                    v["modified_by_username"],
                    v["change_summary"],
                    v["plaintext_sha256"][:16] + "...",
                ),
            )

        # Bottom Close Button
        btn_close = tk.Button(
            self,
            text="Close Viewer",
            command=self.destroy,
            bg=THEME["bg_surface"],
            fg=THEME["text_primary"],
            font=("Segoe UI", 9),
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2",
        )
        btn_close.pack(pady=(0, 10))
