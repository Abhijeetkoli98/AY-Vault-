"""
AY Vault - Administrative Controls & Disaster Recovery View
Identity administration (user creation, role modifications, password resets)
and encrypted backup creation/restoration with manifest verification.
"""

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable
from auth.password_manager import get_password_manager
from auth.session_manager import UserSession
from backup.backup_manager import get_backup_manager
from backup.recovery_manager import get_recovery_manager
from config.settings import CLASSIFICATION_LEVELS, DEPARTMENTS, SYSTEM_ROLES, THEME
from security.access_control import VaultAction
from security.policy_engine import get_policy_engine
from security.security_utils import format_file_size
from ui.components import PolicyDecisionDialog, create_badge
from users.user_manager import get_user_manager


class AdminView(tk.Frame):
    """Admin operations: User Management and Encrypted Backup & Recovery."""

    def __init__(
        self,
        parent: tk.Widget,
        session: UserSession,
        nav_callback: Callable[[str], None],
    ):
        super().__init__(parent, bg=THEME["bg_dark"])
        self.session = session
        self.nav_callback = nav_callback
        self.user_mgr = get_user_manager()
        self.backup_mgr = get_backup_manager()
        self.recovery_mgr = get_recovery_manager()
        self.policy = get_policy_engine()
        self.pwd_mgr = get_password_manager()

        self._build_ui()
        self._load_users()
        self._load_backups()

    def _build_ui(self):
        # Top Header
        top = tk.Frame(self, bg=THEME["bg_dark"])
        top.pack(fill="x", padx=24, pady=(20, 16))

        title_frame = tk.Frame(top, bg=THEME["bg_dark"])
        title_frame.pack(side="left")

        tk.Label(
            title_frame,
            text="ADMINISTRATION & DISASTER RECOVERY",
            font=("Segoe UI", 16, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_dark"],
        ).pack(anchor="w")

        tk.Label(
            title_frame,
            text="Identity Lifecycle, Role-Based Access Control & Encrypted Vault Backups",
            font=("Segoe UI", 9),
            fg=THEME["text_secondary"],
            bg=THEME["bg_dark"],
        ).pack(anchor="w")

        # Notebook Tabs
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=24, pady=(0, 24))

        # Tab 1: User & Identity Management
        user_tab = tk.Frame(notebook, bg=THEME["bg_dark"], padx=14, pady=14)
        notebook.add(user_tab, text="👥 Identity & RBAC Management")

        # User Tab Action Bar
        u_bar = tk.Frame(user_tab, bg=THEME["bg_dark"])
        u_bar.pack(fill="x", pady=(0, 12))

        btn_add_u = tk.Button(
            u_bar,
            text="➕ Provision New User",
            command=self._handle_add_user,
            bg=THEME["primary"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=6,
        )
        btn_add_u.pack(side="left", padx=(0, 6))

        btn_edit_u = tk.Button(
            u_bar,
            text="✏️ Edit Role / Clearance",
            command=self._handle_edit_user,
            bg=THEME["bg_surface"],
            fg=THEME["text_primary"],
            font=("Segoe UI", 9),
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=6,
        )
        btn_edit_u.pack(side="left", padx=4)

        btn_reset_pwd = tk.Button(
            u_bar,
            text="🔑 Reset Password",
            command=self._handle_reset_pwd,
            bg=THEME["bg_surface"],
            fg=THEME["text_primary"],
            font=("Segoe UI", 9),
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=6,
        )
        btn_reset_pwd.pack(side="left", padx=4)

        btn_unlock = tk.Button(
            u_bar,
            text="🔓 Unlock Account",
            command=self._handle_unlock_user,
            bg=THEME["bg_surface"],
            fg=THEME["accent_cyan"],
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=6,
        )
        btn_unlock.pack(side="left", padx=4)

        # Users Table
        u_table_card = tk.Frame(
            user_tab,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=12,
            pady=12,
        )
        u_table_card.pack(fill="both", expand=True)

        u_cols = ("id", "username", "name", "role", "dept", "clearance", "failures", "state")
        self.tree_users = ttk.Treeview(
            u_table_card, columns=u_cols, show="headings", height=10
        )
        self.tree_users.heading("id", text="ID")
        self.tree_users.heading("username", text="Username")
        self.tree_users.heading("name", text="Full Name")
        self.tree_users.heading("role", text="Role")
        self.tree_users.heading("dept", text="Department")
        self.tree_users.heading("clearance", text="Clearance Level")
        self.tree_users.heading("failures", text="Failed Logins")
        self.tree_users.heading("state", text="Account State")

        self.tree_users.column("id", width=40, anchor="center")
        self.tree_users.column("username", width=110)
        self.tree_users.column("name", width=150)
        self.tree_users.column("role", width=90, anchor="center")
        self.tree_users.column("dept", width=100, anchor="center")
        self.tree_users.column("clearance", width=120, anchor="center")
        self.tree_users.column("failures", width=90, anchor="center")
        self.tree_users.column("state", width=100, anchor="center")

        self.tree_users.pack(fill="both", expand=True)

        # Tab 2: Encrypted Backup & Disaster Recovery
        backup_tab = tk.Frame(notebook, bg=THEME["bg_dark"], padx=14, pady=14)
        notebook.add(backup_tab, text="💾 Encrypted Backup & Recovery")

        b_bar = tk.Frame(backup_tab, bg=THEME["bg_dark"])
        b_bar.pack(fill="x", pady=(0, 12))

        btn_create_b = tk.Button(
            b_bar,
            text="🔒 Create Encrypted Backup Archive (.ayb)",
            command=self._handle_create_backup,
            bg=THEME["primary"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            padx=14,
            pady=6,
        )
        btn_create_b.pack(side="left", padx=(0, 8))

        btn_restore_b = tk.Button(
            b_bar,
            text="♻️ Restore System from Backup Archive",
            command=self._handle_restore_backup,
            bg=THEME["danger"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            padx=14,
            pady=6,
        )
        btn_restore_b.pack(side="left", padx=4)

        # Backup History Table
        b_table_card = tk.Frame(
            backup_tab,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=12,
            pady=12,
        )
        b_table_card.pack(fill="both", expand=True)

        b_cols = ("filename", "size", "created", "path")
        self.tree_backups = ttk.Treeview(
            b_table_card, columns=b_cols, show="headings", height=10
        )
        self.tree_backups.heading("filename", text="Archive Filename")
        self.tree_backups.heading("size", text="Encrypted Size")
        self.tree_backups.heading("created", text="Created At (UTC)")
        self.tree_backups.heading("path", text="Storage Location")

        self.tree_backups.column("filename", width=220)
        self.tree_backups.column("size", width=100, anchor="center")
        self.tree_backups.column("created", width=150)
        self.tree_backups.column("path", width=340)

        self.tree_backups.pack(fill="both", expand=True)

    def _load_users(self):
        for item in self.tree_users.get_children():
            self.tree_users.delete(item)

        users, decision = self.user_mgr.list_users(self.session)
        if not decision.is_permitted:
            return

        for u in users:
            state_str = "LOCKED (5 failures)" if u["is_locked"] else "ACTIVE"
            self.tree_users.insert(
                "",
                "end",
                values=(
                    u["id"],
                    u["username"],
                    u["full_name"],
                    u["role"],
                    u["department"],
                    u["clearance_level"],
                    u["failed_login_attempts"],
                    state_str,
                ),
            )

    def _load_backups(self):
        for item in self.tree_backups.get_children():
            self.tree_backups.delete(item)

        backups = self.backup_mgr.list_backups()
        for b in backups:
            self.tree_backups.insert(
                "",
                "end",
                values=(
                    b["filename"],
                    format_file_size(b["size_bytes"]),
                    b["created_at"][:19].replace("T", " "),
                    b["path"],
                ),
            )

    def _get_selected_user(self) -> dict:
        sel = self.tree_users.selection()
        if not sel:
            messagebox.showinfo("Select User", "Please select a user from the table first.")
            return {}
        vals = self.tree_users.item(sel[0], "values")
        return {"id": int(vals[0]), "username": vals[1], "role": vals[3], "dept": vals[4], "clearance": vals[5]}

    def _handle_add_user(self):
        dec = self.policy.evaluate(self.session, VaultAction.USER_MANAGE)
        if not dec.is_permitted:
            PolicyDecisionDialog(self, dec)
            return

        win = tk.Toplevel(self)
        win.title("Provision New Enterprise User")
        win.geometry("440x440")
        win.configure(bg=THEME["bg_dark"])
        win.transient(self)
        win.grab_set()

        fields = [
            ("Username *", "entry_u"),
            ("Temporary Password *", "entry_p"),
            ("Full Name *", "entry_fn"),
        ]
        entries = {}

        for label_text, var_name in fields:
            tk.Label(
                win, text=label_text, font=("Segoe UI", 8, "bold"), fg=THEME["text_secondary"], bg=THEME["bg_dark"]
            ).pack(anchor="w", padx=20, pady=(10, 2))
            ent = tk.Entry(
                win,
                bg=THEME["bg_input"],
                fg=THEME["text_primary"],
                insertbackground=THEME["text_primary"],
                font=("Segoe UI", 9),
                relief="solid",
                highlightbackground=THEME["border"],
                highlightthickness=1,
            )
            ent.pack(fill="x", padx=20, ipady=3)
            entries[var_name] = ent

        entries["entry_p"].insert(0, "TempUser@AYVault2026!")

        # Role Combobox
        tk.Label(win, text="Role *", font=("Segoe UI", 8, "bold"), fg=THEME["text_secondary"], bg=THEME["bg_dark"]).pack(
            anchor="w", padx=20, pady=(10, 2)
        )
        combo_r = ttk.Combobox(win, values=SYSTEM_ROLES, state="readonly")
        combo_r.set(SYSTEM_ROLES[2])  # Viewer
        combo_r.pack(fill="x", padx=20)

        # Department Combobox
        tk.Label(win, text="Department *", font=("Segoe UI", 8, "bold"), fg=THEME["text_secondary"], bg=THEME["bg_dark"]).pack(
            anchor="w", padx=20, pady=(10, 2)
        )
        combo_d = ttk.Combobox(win, values=DEPARTMENTS, state="readonly")
        combo_d.set(DEPARTMENTS[0])
        combo_d.pack(fill="x", padx=20)

        # Clearance Combobox
        tk.Label(win, text="Clearance Level *", font=("Segoe UI", 8, "bold"), fg=THEME["text_secondary"], bg=THEME["bg_dark"]).pack(
            anchor="w", padx=20, pady=(10, 2)
        )
        combo_c = ttk.Combobox(win, values=CLASSIFICATION_LEVELS, state="readonly")
        combo_c.set(CLASSIFICATION_LEVELS[0])
        combo_c.pack(fill="x", padx=20)

        def _do_submit():
            u = entries["entry_u"].get().strip()
            p = entries["entry_p"].get()
            fn = entries["entry_fn"].get().strip()
            role = combo_r.get()
            dept = combo_d.get()
            clearance = combo_c.get()

            succ, decision, msg = self.user_mgr.create_user(
                username=u,
                password=p,
                full_name=fn,
                role=role,
                department=dept,
                clearance_level=clearance,
                session=self.session,
            )
            if succ:
                messagebox.showinfo("User Created", f"User '{u}' successfully created.")
                win.destroy()
                self._load_users()
            else:
                messagebox.showerror("Error", msg)

        tk.Button(
            win,
            text="Create User Account",
            command=_do_submit,
            bg=THEME["primary"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            pady=8,
        ).pack(fill="x", padx=20, pady=(18, 0))

    def _handle_edit_user(self):
        user = self._get_selected_user()
        if not user:
            return

        win = tk.Toplevel(self)
        win.title(f"Modify Attributes - {user['username']}")
        win.geometry("380x300")
        win.configure(bg=THEME["bg_dark"])
        win.transient(self)
        win.grab_set()

        tk.Label(
            win,
            text=f"Editing: {user['username']}",
            font=("Segoe UI", 11, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_dark"],
        ).pack(padx=20, pady=(14, 10), anchor="w")

        tk.Label(win, text="Role:", font=("Segoe UI", 8, "bold"), fg=THEME["text_secondary"], bg=THEME["bg_dark"]).pack(
            anchor="w", padx=20, pady=(4, 2)
        )
        combo_r = ttk.Combobox(win, values=SYSTEM_ROLES, state="readonly")
        combo_r.set(user["role"])
        combo_r.pack(fill="x", padx=20)

        tk.Label(win, text="Department:", font=("Segoe UI", 8, "bold"), fg=THEME["text_secondary"], bg=THEME["bg_dark"]).pack(
            anchor="w", padx=20, pady=(6, 2)
        )
        combo_d = ttk.Combobox(win, values=DEPARTMENTS, state="readonly")
        combo_d.set(user["dept"])
        combo_d.pack(fill="x", padx=20)

        tk.Label(win, text="Clearance Level:", font=("Segoe UI", 8, "bold"), fg=THEME["text_secondary"], bg=THEME["bg_dark"]).pack(
            anchor="w", padx=20, pady=(6, 2)
        )
        combo_c = ttk.Combobox(win, values=CLASSIFICATION_LEVELS, state="readonly")
        combo_c.set(user["clearance"])
        combo_c.pack(fill="x", padx=20)

        def _do_update():
            succ, dec, msg = self.user_mgr.update_user_attributes(
                target_user_id=user["id"],
                role=combo_r.get(),
                department=combo_d.get(),
                clearance_level=combo_c.get(),
                session=self.session,
            )
            if succ:
                messagebox.showinfo("Success", msg)
                win.destroy()
                self._load_users()
            else:
                messagebox.showerror("Error", msg)

        tk.Button(
            win,
            text="Save Modifications",
            command=_do_update,
            bg=THEME["primary"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            pady=6,
        ).pack(fill="x", padx=20, pady=(16, 0))

    def _handle_reset_pwd(self):
        user = self._get_selected_user()
        if not user:
            return

        win = tk.Toplevel(self)
        win.title(f"Reset Password - {user['username']}")
        win.geometry("380x220")
        win.configure(bg=THEME["bg_dark"])
        win.transient(self)
        win.grab_set()

        tk.Label(
            win,
            text=f"Set New Password for '{user['username']}':",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_dark"],
        ).pack(padx=20, pady=(16, 8), anchor="w")

        ent_p = tk.Entry(
            win,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=("Segoe UI", 9),
            relief="solid",
            highlightbackground=THEME["border"],
            highlightthickness=1,
        )
        ent_p.pack(fill="x", padx=20, ipady=4, pady=(0, 16))
        ent_p.insert(0, "NewPass@AYVault2026!")

        def _do_reset():
            new_p = ent_p.get()
            succ, dec, msg = self.user_mgr.reset_user_password(user["id"], new_p, self.session)
            if succ:
                messagebox.showinfo("Success", msg)
                win.destroy()
                self._load_users()
            else:
                messagebox.showerror("Error", msg)

        tk.Button(
            win,
            text="Commit Password Reset",
            command=_do_reset,
            bg=THEME["primary"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            pady=6,
        ).pack(fill="x", padx=20)

    def _handle_unlock_user(self):
        user = self._get_selected_user()
        if not user:
            return

        succ, dec, msg = self.user_mgr.unlock_user(user["id"], self.session)
        if succ:
            messagebox.showinfo("Success", msg)
            self._load_users()
        else:
            PolicyDecisionDialog(self, dec)

    def _handle_create_backup(self):
        dec = self.policy.evaluate(self.session, VaultAction.BACKUP_CREATE)
        if not dec.is_permitted:
            PolicyDecisionDialog(self, dec)
            return

        # Prompt for Passphrase
        win = tk.Toplevel(self)
        win.title("Encrypted Backup Passphrase")
        win.geometry("420x220")
        win.configure(bg=THEME["bg_dark"])
        win.transient(self)
        win.grab_set()

        tk.Label(
            win,
            text="Enter Passphrase to Encrypt Backup Archive (.ayb):",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_dark"],
        ).pack(padx=20, pady=(16, 4), anchor="w")

        tk.Label(
            win,
            text="Derives a 256-bit AES-GCM key with PBKDF2-HMAC-SHA256 (200k rounds).",
            font=("Segoe UI", 8),
            fg=THEME["text_secondary"],
            bg=THEME["bg_dark"],
        ).pack(padx=20, pady=(0, 8), anchor="w")

        ent_pass = tk.Entry(
            win,
            show="•",
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=("Segoe UI", 10),
            relief="solid",
            highlightbackground=THEME["border"],
            highlightthickness=1,
        )
        ent_pass.pack(fill="x", padx=20, ipady=4, pady=(0, 16))
        ent_pass.insert(0, "AYVaultMasterBackup2026!")

        def _do_backup():
            passphrase = ent_pass.get()
            if len(passphrase) < 8:
                messagebox.showerror("Error", "Backup passphrase must be at least 8 characters.")
                return

            win.destroy()
            dest, decision, stats = self.backup_mgr.create_encrypted_backup(
                passphrase=passphrase, session=self.session
            )

            if dest:
                messagebox.showinfo(
                    "Backup Complete",
                    f"Encrypted snapshot created successfully!\n\n"
                    f"Archive: {stats['file_name']}\n"
                    f"Files Included: {stats['files_included']}\n"
                    f"Ciphertext SHA-256: {stats['sha256']}\n"
                    f"Size: {format_file_size(stats['size'])}",
                )
                self._load_backups()
            else:
                PolicyDecisionDialog(self, decision)

        tk.Button(
            win,
            text="Generate Encrypted Archive",
            command=_do_backup,
            bg=THEME["primary"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            pady=8,
        ).pack(fill="x", padx=20)

    def _handle_restore_backup(self):
        dec = self.policy.evaluate(self.session, VaultAction.BACKUP_RESTORE)
        if not dec.is_permitted:
            PolicyDecisionDialog(self, dec)
            return

        archive_file = filedialog.askopenfilename(
            title="Select Encrypted AY Vault Backup (.ayb)",
            filetypes=[("AY Vault Backup (*.ayb)", "*.ayb")],
        )
        if not archive_file:
            return

        # Prompt for Passphrase
        win = tk.Toplevel(self)
        win.title("Restore Backup - Decryption Passphrase")
        win.geometry("420x200")
        win.configure(bg=THEME["bg_dark"])
        win.transient(self)
        win.grab_set()

        tk.Label(
            win,
            text="Enter Passphrase to Decrypt & Restore Archive:",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_dark"],
        ).pack(padx=20, pady=(16, 4), anchor="w")

        ent_pass = tk.Entry(
            win,
            show="•",
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=("Segoe UI", 10),
            relief="solid",
            highlightbackground=THEME["border"],
            highlightthickness=1,
        )
        ent_pass.pack(fill="x", padx=20, ipady=4, pady=(0, 16))
        ent_pass.insert(0, "AYVaultMasterBackup2026!")

        def _do_restore():
            passphrase = ent_pass.get()
            win.destroy()

            succ, decision, msg = self.recovery_mgr.restore_backup(
                backup_path=Path(archive_file),
                passphrase=passphrase,
                session=self.session,
            )

            if succ:
                messagebox.showinfo("Restoration Complete", f"System restored successfully!\n\n{msg}")
                self._load_users()
                self._load_backups()
            else:
                messagebox.showerror("Restoration Failed", msg)

        tk.Button(
            win,
            text="Decrypt & Restore System",
            command=_do_restore,
            bg=THEME["danger"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            pady=8,
        ).pack(fill="x", padx=20)
