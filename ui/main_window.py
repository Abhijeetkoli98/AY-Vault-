"""
AY Vault - Main Authenticated Application Window
Provides unified navigation sidebar, user security context, and dynamic view routing.
"""

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, Optional
from auth.authentication import get_auth_service
from auth.session_manager import UserSession
from config.settings import APP_NAME, APP_SUBTITLE, APP_VERSION, THEME
from ui.admin_view import AdminView
from ui.audit_view import AuditView
from ui.components import create_badge
from ui.dashboard_view import DashboardView
from ui.document_view import DocumentView
from ui.security_view import SecurityView
from ui.upload_view import UploadView


class MainWindow(tk.Frame):
    """Main application frame containing the persistent sidebar and view container."""

    def __init__(
        self,
        parent: tk.Widget,
        session: UserSession,
        on_logout: Callable[[], None],
    ):
        super().__init__(parent, bg=THEME["bg_dark"])
        self.session = session
        self.on_logout = on_logout
        self.auth_service = get_auth_service()

        self.current_view_name = "dashboard"
        self.current_view_widget: Optional[tk.Widget] = None

        self._build_layout()
        self.navigate_to("dashboard")

    def _build_layout(self):
        # Left Sidebar Frame
        self.sidebar = tk.Frame(
            self,
            bg=THEME["sidebar_bg"],
            width=240,
            highlightbackground=THEME["border"],
            highlightthickness=1,
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Branding in Sidebar
        brand_frame = tk.Frame(self.sidebar, bg=THEME["sidebar_bg"], padx=18, pady=20)
        brand_frame.pack(fill="x")

        tk.Label(
            brand_frame,
            text=f"🔒 {APP_NAME}",
            font=("Segoe UI", 14, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["sidebar_bg"],
        ).pack(anchor="w")

        tk.Label(
            brand_frame,
            text=f"v{APP_VERSION} • Offline Vault",
            font=("Segoe UI", 8),
            fg=THEME["text_muted"],
            bg=THEME["sidebar_bg"],
        ).pack(anchor="w", pady=(2, 0))

        # Divider
        tk.Frame(self.sidebar, bg=THEME["border"], height=1).pack(fill="x", padx=14, pady=(0, 14))

        # Navigation Buttons
        self.nav_buttons = {}
        nav_items = [
            ("dashboard", "🛡️  Dashboard", "dashboard"),
            ("documents", "📁  Document Vault", "documents"),
            ("upload", "📤  Secure Ingest", "upload"),
            ("audit", "🔗  Audit & Forensics", "audit"),
            ("security", "🧪  Policy Sandbox", "security"),
            ("admin", "⚙️  Administration", "admin"),
        ]

        for key, label, target in nav_items:
            btn = tk.Button(
                self.sidebar,
                text=label,
                command=lambda t=target: self.navigate_to(t),
                bg=THEME["sidebar_bg"],
                activebackground=THEME["sidebar_active"],
                fg=THEME["text_secondary"],
                activeforeground=THEME["text_primary"],
                font=("Segoe UI", 10),
                relief="flat",
                anchor="w",
                padx=18,
                pady=10,
                cursor="hand2",
            )
            btn.pack(fill="x")
            self.nav_buttons[key] = btn

        # Spacer
        tk.Frame(self.sidebar, bg=THEME["sidebar_bg"]).pack(fill="both", expand=True)

        # Bottom Sidebar: User Context & Logout
        bottom_box = tk.Frame(
            self.sidebar,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=14,
            pady=14,
        )
        bottom_box.pack(fill="x", padx=10, pady=10)

        tk.Label(
            bottom_box,
            text=f"👤 {self.session.full_name}",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_card"],
        ).pack(anchor="w")

        tk.Label(
            bottom_box,
            text=f"@{self.session.username} • {self.session.department}",
            font=("Segoe UI", 8),
            fg=THEME["text_muted"],
            bg=THEME["bg_card"],
        ).pack(anchor="w", pady=(1, 6))

        badges_frame = tk.Frame(bottom_box, bg=THEME["bg_card"])
        badges_frame.pack(fill="x", pady=(0, 10))

        create_badge(badges_frame, self.session.role).pack(side="left", padx=(0, 4))
        create_badge(badges_frame, self.session.clearance_level).pack(side="left")

        btn_logout = tk.Button(
            bottom_box,
            text="🚪 Terminate Session",
            command=self._handle_logout,
            bg=THEME["bg_surface"],
            fg=THEME["danger"],
            font=("Segoe UI", 8, "bold"),
            relief="flat",
            cursor="hand2",
            pady=4,
        )
        btn_logout.pack(fill="x")

        # Right Main Content Container
        self.content_container = tk.Frame(self, bg=THEME["bg_dark"])
        self.content_container.pack(side="right", fill="both", expand=True)

    def navigate_to(self, view_name: str):
        """Swaps the current view with the target view."""
        self.current_view_name = view_name

        # Highlight active nav button
        for key, btn in self.nav_buttons.items():
            if key == view_name:
                btn.config(
                    bg=THEME["sidebar_active"],
                    fg=THEME["accent_cyan"],
                    font=("Segoe UI", 10, "bold"),
                )
            else:
                btn.config(
                    bg=THEME["sidebar_bg"],
                    fg=THEME["text_secondary"],
                    font=("Segoe UI", 10),
                )

        # Clear existing view
        if self.current_view_widget:
            self.current_view_widget.destroy()

        # Instantiate new view
        if view_name == "dashboard":
            self.current_view_widget = DashboardView(
                self.content_container, self.session, self.navigate_to
            )
        elif view_name == "documents":
            self.current_view_widget = DocumentView(
                self.content_container, self.session, self.navigate_to
            )
        elif view_name == "upload":
            self.current_view_widget = UploadView(
                self.content_container, self.session, self.navigate_to
            )
        elif view_name == "audit":
            self.current_view_widget = AuditView(
                self.content_container, self.session, self.navigate_to
            )
        elif view_name == "security":
            self.current_view_widget = SecurityView(
                self.content_container, self.session, self.navigate_to
            )
        elif view_name == "admin":
            self.current_view_widget = AdminView(
                self.content_container, self.session, self.navigate_to
            )
        else:
            self.current_view_widget = DashboardView(
                self.content_container, self.session, self.navigate_to
            )

        self.current_view_widget.pack(fill="both", expand=True)

    def _handle_logout(self):
        confirm = messagebox.askyesno(
            "Terminate Session", "Are you sure you want to log out and lock the vault interface?"
        )
        if confirm:
            self.auth_service.logout()
            self.on_logout()
