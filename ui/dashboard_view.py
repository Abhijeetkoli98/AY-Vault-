"""
AY Vault - Security Dashboard View
High-level overview of vault metrics, cryptographic integrity status,
lockout monitors, and live security audit feed.
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable
from audit.audit_logger import get_audit_logger
from audit.audit_verifier import get_audit_verifier
from auth.session_manager import UserSession
from config.settings import THEME
from database.database import get_db
from documents.document_storage import get_doc_storage
from security.security_utils import format_file_size
from ui.components import StatCard, create_badge


class DashboardView(tk.Frame):
    """Main dashboard displaying security metrics and recent audit activity."""

    def __init__(
        self,
        parent: tk.Widget,
        session: UserSession,
        nav_callback: Callable[[str], None],
    ):
        super().__init__(parent, bg=THEME["bg_dark"])
        self.session = session
        self.nav_callback = nav_callback
        self.db = get_db()
        self.storage = get_doc_storage()
        self.verifier = get_audit_verifier()
        self.audit_logger = get_audit_logger()

        self._build_ui()

    def _build_ui(self):
        # Top Header & User Context Banner
        top_header = tk.Frame(self, bg=THEME["bg_dark"])
        top_header.pack(fill="x", padx=24, pady=(20, 16))

        title_frame = tk.Frame(top_header, bg=THEME["bg_dark"])
        title_frame.pack(side="left")

        tk.Label(
            title_frame,
            text="SECURITY COMMAND CENTER",
            font=("Segoe UI", 16, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_dark"],
        ).pack(anchor="w")

        tk.Label(
            title_frame,
            text="Offline Cryptographic Defense, Multilevel Access Control & Forensics",
            font=("Segoe UI", 9),
            fg=THEME["text_secondary"],
            bg=THEME["bg_dark"],
        ).pack(anchor="w")

        # User Context Card
        user_card = tk.Frame(
            top_header,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=14,
            pady=8,
        )
        user_card.pack(side="right")

        tk.Label(
            user_card,
            text=f"👤 {self.session.full_name} ({self.session.username})",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_card"],
        ).pack(anchor="e")

        badge_row = tk.Frame(user_card, bg=THEME["bg_card"])
        badge_row.pack(anchor="e", pady=(4, 0))

        create_badge(badge_row, self.session.role).pack(side="right", padx=(4, 0))
        create_badge(badge_row, self.session.clearance_level).pack(side="right", padx=(4, 0))
        create_badge(badge_row, f"Dept: {self.session.department}", "neutral").pack(side="right")

        # Stat Cards Grid (4 columns)
        stats_frame = tk.Frame(self, bg=THEME["bg_dark"])
        stats_frame.pack(fill="x", padx=24, pady=(0, 20))
        stats_frame.columnconfigure((0, 1, 2, 3), weight=1, uniform="stat_cols")

        # Load metrics
        doc_count_row = self.db.fetch_one("SELECT COUNT(*) as cnt FROM documents WHERE is_deleted = 0;")
        total_docs = doc_count_row["cnt"] if doc_count_row else 0

        vault_stats = self.storage.get_vault_stats()
        storage_formatted = format_file_size(vault_stats["total_bytes"])

        # Quick audit check
        audit_rep = self.verifier.verify_integrity()
        chain_status_text = "VERIFIED (100%)" if audit_rep.is_valid else "COMPROMISED"
        chain_color = THEME["success"] if audit_rep.is_valid else THEME["danger"]

        locked_users_row = self.db.fetch_one("SELECT COUNT(*) as cnt FROM users WHERE is_locked = 1;")
        locked_count = locked_users_row["cnt"] if locked_users_row else 0

        # Card 1: Vaulted Docs
        c1 = StatCard(
            stats_frame,
            title="Encrypted Documents",
            value=str(total_docs),
            subtitle="AES-256-GCM at rest",
            accent_color=THEME["primary"],
            icon="📁",
        )
        c1.grid(row=0, column=0, padx=(0, 10), sticky="nsew")

        # Card 2: Ciphertext Storage
        c2 = StatCard(
            stats_frame,
            title="Vault Ciphertext",
            value=storage_formatted,
            subtitle=f"{vault_stats['total_files']} encrypted payloads",
            accent_color=THEME["accent_cyan"],
            icon="💾",
        )
        c2.grid(row=0, column=1, padx=(0, 10), sticky="nsew")

        # Card 3: Audit Ledger Integrity
        c3 = StatCard(
            stats_frame,
            title="Audit Chain Integrity",
            value=chain_status_text,
            subtitle=f"{audit_rep.total_records} chained SHA-256 blocks",
            accent_color=chain_color,
            icon="🔗",
        )
        c3.grid(row=0, column=2, padx=(0, 10), sticky="nsew")

        # Card 4: Lockouts & Security Alerts
        c4 = StatCard(
            stats_frame,
            title="Account Lockouts",
            value=str(locked_count),
            subtitle="5 consecutive failures policy",
            accent_color=THEME["warning"] if locked_count > 0 else THEME["success"],
            icon="⚠️",
        )
        c4.grid(row=0, column=3, sticky="nsew")

        # Quick Navigation / Action Bar
        action_bar = tk.Frame(
            self,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=16,
            pady=12,
        )
        action_bar.pack(fill="x", padx=24, pady=(0, 20))

        tk.Label(
            action_bar,
            text="QUICK SECURITY ACTIONS:",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["accent_cyan"],
            bg=THEME["bg_card"],
        ).pack(side="left", padx=(0, 16))

        actions = [
            ("📁 Explore Vault", "documents"),
            ("📤 Ingest Encrypted Document", "upload"),
            ("🔗 Verify Audit Chain", "audit"),
            ("🛡️ Policy Sandbox", "security"),
            ("⚙️ User & Backup Admin", "admin"),
        ]

        for label, target in actions:
            btn = tk.Button(
                action_bar,
                text=label,
                font=("Segoe UI", 9),
                bg=THEME["bg_surface"],
                fg=THEME["text_primary"],
                relief="flat",
                cursor="hand2",
                padx=12,
                pady=6,
                command=lambda t=target: self.nav_callback(t),
            )
            btn.pack(side="left", padx=4)

        # Bottom Section: Live Audit Feed Table
        feed_frame = tk.Frame(
            self,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=16,
            pady=16,
        )
        feed_frame.pack(fill="both", expand=True, padx=24, pady=(0, 24))

        feed_top = tk.Frame(feed_frame, bg=THEME["bg_card"])
        feed_top.pack(fill="x", pady=(0, 10))

        tk.Label(
            feed_top,
            text="RECENT SECURITY AUDIT TRAIL",
            font=("Segoe UI", 11, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_card"],
        ).pack(side="left")

        tk.Button(
            feed_top,
            text="View Full Hash Chain →",
            font=("Segoe UI", 8, "bold"),
            bg=THEME["bg_card"],
            fg=THEME["accent_cyan"],
            relief="flat",
            cursor="hand2",
            command=lambda: self.nav_callback("audit"),
        ).pack(side="right")

        # Treeview table for recent audit events
        columns = ("id", "timestamp", "event", "user", "action", "resource", "status")
        self.tree = ttk.Treeview(feed_frame, columns=columns, show="headings", height=8)

        self.tree.heading("id", text="#")
        self.tree.heading("timestamp", text="Timestamp (UTC)")
        self.tree.heading("event", text="Event Type")
        self.tree.heading("user", text="Operator")
        self.tree.heading("action", text="Action")
        self.tree.heading("resource", text="Resource")
        self.tree.heading("status", text="Status")

        self.tree.column("id", width=36, anchor="center")
        self.tree.column("timestamp", width=140)
        self.tree.column("event", width=120)
        self.tree.column("user", width=90)
        self.tree.column("action", width=180)
        self.tree.column("resource", width=120)
        self.tree.column("status", width=80, anchor="center")

        self.tree.pack(fill="both", expand=True)

        self._load_recent_events()

    def _load_recent_events(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        recent = self.audit_logger.get_recent_events(limit=15)
        for r in recent:
            self.tree.insert(
                "",
                "end",
                values=(
                    r["id"],
                    r["timestamp"][:19].replace("T", " "),
                    r["event_type"],
                    r["username"],
                    r["action"],
                    f"{r['resource_type']}:{r['resource_id'] or ''}",
                    r["status"],
                ),
            )
