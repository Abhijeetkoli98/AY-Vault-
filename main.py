"""
AY Vault - Secure Offline Document Management System
Application entry point: initializes system directories, database schema,
seeding, styles, and controls authentication view transitions.
"""

import sys
import tkinter as tk
from tkinter import messagebox
from auth.authentication import get_auth_service
from auth.session_manager import UserSession
from config.settings import APP_NAME, APP_SUBTITLE, APP_VERSION, THEME
from database.database import get_db
from database.seed import seed_database
from ui.login_view import LoginView
from ui.main_window import MainWindow
from ui.styles import configure_theme


class AYVaultApp:
    """Root Application Controller."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME} — {APP_SUBTITLE} [v{APP_VERSION}]")
        self.root.geometry("1240x780")
        self.root.minsize(1080, 680)

        # Configure global theme styling
        configure_theme(self.root)

        # Initialize and seed database if necessary
        self._bootstrap_system()

        self.current_frame = None
        self.auth_service = get_auth_service()

        # Handle window close cleanly
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Show initial login interface
        self.show_login()

    def _bootstrap_system(self):
        """Ensures database schema and default records are initialized."""
        try:
            seed_database(force_reseed=False)
        except Exception as e:
            messagebox.showerror(
                "Bootstrap Error",
                f"Failed to initialize vault database:\n{str(e)}",
            )
            sys.exit(1)

    def show_login(self):
        """Renders the secure login interface."""
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = LoginView(
            self.root, on_login_success=self.show_main_vault
        )
        self.current_frame.pack(fill="both", expand=True)

    def show_main_vault(self, session: UserSession):
        """Renders the main authenticated vault application."""
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = MainWindow(
            self.root, session=session, on_logout=self.show_login
        )
        self.current_frame.pack(fill="both", expand=True)

    def _on_close(self):
        """Handles application shutdown cleanly."""
        try:
            self.auth_service.logout()
            get_db().close()
        except Exception:
            pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = AYVaultApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
