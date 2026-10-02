"""
AY Vault - Login View
Handles user authentication, demo credential shortcuts, lockout indicators,
and security status feedback.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable, Optional
from auth.authentication import get_auth_service
from auth.session_manager import UserSession
from config.settings import THEME


class LoginView(tk.Frame):
    """Secure login interface with credential shortcuts and lockout warnings."""

    def __init__(self, parent: tk.Widget, on_login_success: Callable[[UserSession], None]):
        super().__init__(parent, bg=THEME["bg_dark"])
        self.on_login_success = on_login_success
        self.auth_service = get_auth_service()

        self._build_ui()

    def _build_ui(self):
        # Outer centering frame
        center_frame = tk.Frame(self, bg=THEME["bg_dark"])
        center_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Main Card
        card = tk.Frame(
            center_frame,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=36,
            pady=32,
            width=460,
        )
        card.pack()

        # Branding Header
        lbl_shield = tk.Label(
            card,
            text="🔒",
            font=("Segoe UI", 32),
            bg=THEME["bg_card"],
            fg=THEME["primary"],
        )
        lbl_shield.pack(pady=(0, 4))

        lbl_app = tk.Label(
            card,
            text="AY VAULT",
            font=("Segoe UI", 18, "bold"),
            bg=THEME["bg_card"],
            fg=THEME["text_primary"],
        )
        lbl_app.pack()

        lbl_sub = tk.Label(
            card,
            text="Secure Offline Document Management System",
            font=("Segoe UI", 9),
            bg=THEME["bg_card"],
            fg=THEME["text_secondary"],
        )
        lbl_sub.pack(pady=(0, 16))

        # Status / Lockout Alert Banner
        self.alert_frame = tk.Frame(card, bg=THEME["bg_card"])
        self.alert_frame.pack(fill="x", pady=(0, 12))

        self.lbl_alert = tk.Label(
            self.alert_frame,
            text="",
            font=("Segoe UI", 9, "bold"),
            wraplength=380,
            justify="center",
            bg=THEME["bg_card"],
        )
        self.lbl_alert.pack()

        # Username Input
        lbl_u = tk.Label(
            card,
            text="USERNAME",
            font=("Segoe UI", 8, "bold"),
            bg=THEME["bg_card"],
            fg=THEME["text_secondary"],
            anchor="w",
        )
        lbl_u.pack(fill="x", pady=(4, 2))

        self.entry_user = tk.Entry(
            card,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            insertbackground=THEME["text_primary"],
            font=("Segoe UI", 10),
            relief="solid",
            highlightbackground=THEME["border"],
            highlightcolor=THEME["border_focus"],
            highlightthickness=1,
        )
        self.entry_user.pack(fill="x", ipady=6, pady=(0, 10))

        # Password Input
        lbl_p = tk.Label(
            card,
            text="PASSWORD",
            font=("Segoe UI", 8, "bold"),
            bg=THEME["bg_card"],
            fg=THEME["text_secondary"],
            anchor="w",
        )
        lbl_p.pack(fill="x", pady=(4, 2))

        self.entry_pass = tk.Entry(
            card,
            show="•",
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            insertbackground=THEME["text_primary"],
            font=("Segoe UI", 10),
            relief="solid",
            highlightbackground=THEME["border"],
            highlightcolor=THEME["border_focus"],
            highlightthickness=1,
        )
        self.entry_pass.pack(fill="x", ipady=6, pady=(0, 16))
        self.entry_pass.bind("<Return>", lambda e: self._handle_login())

        # Login Button
        self.btn_login = tk.Button(
            card,
            text="AUTHENTICATE & UNLOCK VAULT",
            command=self._handle_login,
            bg=THEME["primary"],
            activebackground=THEME["primary_hover"],
            fg="#ffffff",
            activeforeground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            cursor="hand2",
            pady=8,
        )
        self.btn_login.pack(fill="x", pady=(0, 18))

        # Quick Demo Persona Switcher (Convenience for testing requirements)
        demo_frame = tk.Frame(
            card,
            bg=THEME["bg_surface"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=12,
            pady=10,
        )
        demo_frame.pack(fill="x")

        lbl_demo = tk.Label(
            demo_frame,
            text="QUICK DEMO CREDENTIAL SELECTOR:",
            font=("Segoe UI", 8, "bold"),
            bg=THEME["bg_surface"],
            fg=THEME["accent_cyan"],
        )
        lbl_demo.pack(anchor="w", pady=(0, 6))

        btn_grid = tk.Frame(demo_frame, bg=THEME["bg_surface"])
        btn_grid.pack(fill="x")

        personas = [
            ("Admin (Dr. Vance)", "admin", "Admin@AYVault2026!"),
            ("Manager (Sarah)", "sarah_mgr", "Manager@AYVault2026!"),
            ("Viewer (Bob)", "bob_viewer", "Viewer@AYVault2026!"),
            ("Locked User (Dave)", "dave_locked", "Locked@AYVault2026!"),
        ]

        for label, u, p in personas:
            b = tk.Button(
                btn_grid,
                text=label,
                font=("Segoe UI", 8),
                bg=THEME["bg_card"],
                fg=THEME["text_primary"],
                relief="flat",
                cursor="hand2",
                command=lambda user=u, pwd=p: self._fill_credentials(user, pwd),
            )
            b.pack(fill="x", pady=2)

        # Pre-fill with Admin by default
        self._fill_credentials("admin", "Admin@AYVault2026!")

    def _fill_credentials(self, username: str, password: str):
        self.entry_user.delete(0, tk.END)
        self.entry_user.insert(0, username)
        self.entry_pass.delete(0, tk.END)
        self.entry_pass.insert(0, password)
        self.lbl_alert.config(text="")
        self.alert_frame.config(bg=THEME["bg_card"])

    def _handle_login(self):
        username = self.entry_user.get().strip()
        password = self.entry_pass.get()

        res = self.auth_service.login(username, password)

        if res.success and res.session:
            self.lbl_alert.config(text="")
            self.on_login_success(res.session)
        else:
            if res.is_locked:
                self.alert_frame.config(bg=THEME["danger_bg"], padx=8, pady=6)
                self.lbl_alert.config(
                    text=f"⚠️ {res.error_message}",
                    bg=THEME["danger_bg"],
                    fg="#fca5a5",
                )
            else:
                self.alert_frame.config(bg=THEME["warning_bg"], padx=8, pady=6)
                self.lbl_alert.config(
                    text=f"⚠️ {res.error_message}",
                    bg=THEME["warning_bg"],
                    fg="#fde68a",
                )
