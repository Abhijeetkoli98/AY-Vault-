"""
AY Vault - Security Center & Policy Simulator View
Displays cryptographic subsystem health, account lockout controls,
and provides an interactive Live Policy Sandbox to test Bell-LaPadula MLS & Compartmentalization rules.
"""

from datetime import datetime, timezone
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable
from auth.authentication import get_auth_service
from auth.session_manager import UserSession
from config.settings import THEME
from database.database import get_db
from security.access_control import VaultAction
from security.policy_engine import PolicyDecision, get_policy_engine
from ui.components import PolicyDecisionDialog, StatCard, create_badge


class SecurityView(tk.Frame):
    """Security Center interface with Policy Simulator and Lockout Manager."""

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
        self.policy = get_policy_engine()
        self.auth_service = get_auth_service()

        self._build_ui()
        self._load_lockout_table()

    def _build_ui(self):
        # Top Header
        top = tk.Frame(self, bg=THEME["bg_dark"])
        top.pack(fill="x", padx=24, pady=(20, 16))

        title_frame = tk.Frame(top, bg=THEME["bg_dark"])
        title_frame.pack(side="left")

        tk.Label(
            title_frame,
            text="SECURITY CENTER & POLICY ENGINE",
            font=("Segoe UI", 16, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_dark"],
        ).pack(anchor="w")

        tk.Label(
            title_frame,
            text="Cryptographic Specifications, Live Policy Simulator & Identity Lockout Monitor",
            font=("Segoe UI", 9),
            fg=THEME["text_secondary"],
            bg=THEME["bg_dark"],
        ).pack(anchor="w")

        # Two-column container
        container = tk.Frame(self, bg=THEME["bg_dark"])
        container.pack(fill="both", expand=True, padx=24, pady=(0, 24))
        container.columnconfigure((0, 1), weight=1)

        # LEFT COLUMN: Live Policy Sandbox / Simulator
        left_col = tk.Frame(container, bg=THEME["bg_dark"])
        left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 12))

        sandbox_card = tk.Frame(
            left_col,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=20,
            pady=20,
        )
        sandbox_card.pack(fill="both", expand=True)

        tk.Label(
            sandbox_card,
            text="🧪 LIVE POLICY SIMULATION SANDBOX",
            font=("Segoe UI", 11, "bold"),
            fg=THEME["accent_cyan"],
            bg=THEME["bg_card"],
        ).pack(anchor="w", pady=(0, 4))

        tk.Label(
            sandbox_card,
            text="Test how the Bell-LaPadula MLS & Compartmentalization engine evaluates arbitrary subject/action pairs:",
            font=("Segoe UI", 8),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
            wraplength=420,
            justify="left",
        ).pack(anchor="w", pady=(0, 16))

        # Subject Selector
        tk.Label(
            sandbox_card,
            text="SUBJECT USER:",
            font=("Segoe UI", 8, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        ).pack(anchor="w", pady=(0, 4))

        self.users_list = self.db.fetch_all("SELECT * FROM users ORDER BY id ASC;")
        user_labels = [f"{u['username']} ({u['role']} - {u['clearance_level']} - {u['department']})" for u in self.users_list]
        self.combo_sim_user = ttk.Combobox(sandbox_card, values=user_labels, state="readonly")
        if user_labels:
            self.combo_sim_user.set(user_labels[0])
        self.combo_sim_user.pack(fill="x", pady=(0, 12))

        # Document Selector
        tk.Label(
            sandbox_card,
            text="TARGET RESOURCE (DOCUMENT):",
            font=("Segoe UI", 8, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        ).pack(anchor="w", pady=(0, 4))

        self.docs_list = self.db.fetch_all("SELECT * FROM documents WHERE is_deleted = 0 ORDER BY title ASC;")
        doc_labels = [f"{d['title']} [{d['classification_level']}] ({d['department']})" for d in self.docs_list]
        self.combo_sim_doc = ttk.Combobox(sandbox_card, values=doc_labels, state="readonly")
        if doc_labels:
            self.combo_sim_doc.set(doc_labels[0])
        self.combo_sim_doc.pack(fill="x", pady=(0, 12))

        # Action Selector
        tk.Label(
            sandbox_card,
            text="REQUESTED ACTION:",
            font=("Segoe UI", 8, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        ).pack(anchor="w", pady=(0, 4))

        self.sim_actions = [
            ("DOC_READ (View Decrypted Content)", VaultAction.DOC_READ),
            ("DOC_DOWNLOAD (Export Decrypted File)", VaultAction.DOC_DOWNLOAD),
            ("DOC_WRITE (Update/Create Version)", VaultAction.DOC_WRITE),
            ("DOC_DELETE (Soft Delete Document)", VaultAction.DOC_DELETE),
        ]
        self.combo_sim_act = ttk.Combobox(
            sandbox_card, values=[a[0] for a in self.sim_actions], state="readonly"
        )
        self.combo_sim_act.set(self.sim_actions[0][0])
        self.combo_sim_act.pack(fill="x", pady=(0, 16))

        # Run Simulation Button
        btn_eval = tk.Button(
            sandbox_card,
            text="⚡ EVALUATE POLICY DECISION",
            command=self._handle_run_simulation,
            bg=THEME["primary"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            pady=8,
        )
        btn_eval.pack(fill="x", pady=(0, 16))

        # Simulation Decision Output Box
        self.sim_output_frame = tk.Frame(
            sandbox_card,
            bg=THEME["bg_surface"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=14,
            pady=12,
        )
        self.sim_output_frame.pack(fill="both", expand=True)

        self.lbl_sim_status = tk.Label(
            self.sim_output_frame,
            text="Select parameters above and click evaluate.",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_surface"],
            wraplength=400,
            justify="left",
        )
        self.lbl_sim_status.pack(anchor="w", pady=(0, 6))

        self.lbl_sim_details = tk.Label(
            self.sim_output_frame,
            text="",
            font=("Segoe UI", 8),
            fg=THEME["text_primary"],
            bg=THEME["bg_surface"],
            wraplength=400,
            justify="left",
        )
        self.lbl_sim_details.pack(anchor="w")

        # RIGHT COLUMN: Subsystem Specs & Lockout Monitor
        right_col = tk.Frame(container, bg=THEME["bg_dark"])
        right_col.grid(row=0, column=1, sticky="nsew", padx=(12, 0))

        # Cryptographic Specs Card
        specs_card = tk.Frame(
            right_col,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=20,
            pady=16,
        )
        specs_card.pack(fill="x", pady=(0, 16))

        tk.Label(
            specs_card,
            text="🔐 CRYPTOGRAPHIC SPECIFICATIONS",
            font=("Segoe UI", 10, "bold"),
            fg=THEME["accent_cyan"],
            bg=THEME["bg_card"],
        ).pack(anchor="w", pady=(0, 10))

        specs = [
            ("Symmetric Cipher:", "AES-256-GCM (Authenticated AEAD)"),
            ("Nonce Length:", "96-bit Random Nonce / Envelope"),
            ("Password Hashing:", "Argon2id (64MB RAM, t=3, p=4)"),
            ("Ledger Continuity:", "Sequential SHA-256 Merkle Hash Chain"),
            ("Lockout Threshold:", "Strict 5 Consecutive Failed Attempts"),
        ]

        for k, v in specs:
            r = tk.Frame(specs_card, bg=THEME["bg_card"])
            r.pack(fill="x", pady=2)
            tk.Label(
                r,
                text=k,
                font=("Segoe UI", 8, "bold"),
                fg=THEME["text_secondary"],
                bg=THEME["bg_card"],
                width=18,
                anchor="w",
            ).pack(side="left")
            tk.Label(
                r,
                text=v,
                font=("Segoe UI", 8),
                fg=THEME["text_primary"],
                bg=THEME["bg_card"],
            ).pack(side="left")

        # Account Lockout Monitor Card
        lock_card = tk.Frame(
            right_col,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=20,
            pady=16,
        )
        lock_card.pack(fill="both", expand=True)

        lock_head = tk.Frame(lock_card, bg=THEME["bg_card"])
        lock_head.pack(fill="x", pady=(0, 8))

        tk.Label(
            lock_head,
            text="⚠️ ACCOUNT LOCKOUT MONITOR",
            font=("Segoe UI", 10, "bold"),
            fg=THEME["warning"],
            bg=THEME["bg_card"],
        ).pack(side="left")

        btn_unlock = tk.Button(
            lock_head,
            text="🔓 Unlock Selected",
            command=self._handle_unlock_selected,
            bg=THEME["bg_surface"],
            fg=THEME["text_primary"],
            font=("Segoe UI", 8, "bold"),
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=3,
        )
        btn_unlock.pack(side="right")

        self.tree_lock = ttk.Treeview(
            lock_card,
            columns=("user", "failed", "status", "id"),
            show="headings",
            height=6,
        )
        self.tree_lock.heading("user", text="Username")
        self.tree_lock.heading("failed", text="Failed Logins")
        self.tree_lock.heading("status", text="Account State")
        self.tree_lock.heading("id", text="User ID")

        self.tree_lock.column("user", width=120)
        self.tree_lock.column("failed", width=90, anchor="center")
        self.tree_lock.column("status", width=110, anchor="center")
        self.tree_lock.column("id", width=60, anchor="center")

        self.tree_lock.pack(fill="both", expand=True)

    def _load_lockout_table(self):
        for item in self.tree_lock.get_children():
            self.tree_lock.delete(item)

        users = self.db.fetch_all("SELECT * FROM users ORDER BY is_locked DESC, failed_login_attempts DESC;")
        for u in users:
            state_text = "LOCKED" if u["is_locked"] else ("WARNING" if u["failed_login_attempts"] > 0 else "NORMAL")
            self.tree_lock.insert(
                "",
                "end",
                values=(
                    u["username"],
                    f"{u['failed_login_attempts']} / 5",
                    state_text,
                    u["id"],
                ),
            )

    def _handle_run_simulation(self):
        sim_user_idx = self.combo_sim_user.current()
        sim_doc_idx = self.combo_sim_doc.current()
        sim_act_idx = self.combo_sim_act.current()

        if sim_user_idx < 0 or sim_doc_idx < 0 or sim_act_idx < 0:
            return

        target_user = self.users_list[sim_user_idx]
        target_doc = self.docs_list[sim_doc_idx]
        action_val = self.sim_actions[sim_act_idx][1]

        # Construct simulated session
        sim_session = UserSession(
            user_id=target_user["id"],
            username=target_user["username"],
            full_name=target_user["full_name"],
            role=target_user["role"],
            department=target_user["department"],
            clearance_level=target_user["clearance_level"],
            token="sim_token_12345",
            created_at=datetime.now(timezone.utc),
            last_activity=datetime.now(timezone.utc),
        )

        decision = self.policy.evaluate(
            sim_session,
            action_val,
            resource=dict(target_doc),
            context={"is_simulation": True},
            log_denial=False,
        )

        if decision.is_permitted:
            self.sim_output_frame.config(bg=THEME["success_bg"])
            self.lbl_sim_status.config(
                text="✓ ACCESS PERMITTED",
                fg="#a7f3d0",
                bg=THEME["success_bg"],
            )
        else:
            self.sim_output_frame.config(bg=THEME["danger_bg"])
            self.lbl_sim_status.config(
                text="⛔ ACCESS DENIED",
                fg="#fca5a5",
                bg=THEME["danger_bg"],
            )

        details_text = (
            f"Rule Enforced:  {decision.rule_name}\n"
            f"Decision Code:  {decision.decision_code}\n\n"
            f"Rationale:\n{decision.reason}"
        )
        self.lbl_sim_details.config(
            text=details_text,
            bg=self.sim_output_frame.cget("bg"),
            fg=THEME["text_primary"],
        )

    def _handle_unlock_selected(self):
        if self.session.role != "Admin":
            messagebox.showerror(
                "Access Denied",
                "Only System Administrators are authorized to unlock user accounts.",
            )
            return

        selection = self.tree_lock.selection()
        if not selection:
            messagebox.showinfo("Select Account", "Please select a user account to unlock.")
            return

        row_vals = self.tree_lock.item(selection[0], "values")
        user_id = int(row_vals[3])
        username = row_vals[0]

        succ = self.auth_service.unlock_user_account(user_id, self.session)
        if succ:
            messagebox.showinfo(
                "Account Unlocked",
                f"Account '{username}' has been unlocked and failed login counter reset.",
            )
            self._load_lockout_table()
        else:
            messagebox.showerror("Error", "Failed to unlock user account.")
