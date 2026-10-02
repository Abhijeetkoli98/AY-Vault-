"""
AY Vault - Audit Ledger & Forensics View
Displays the immutable hash-chained audit ledger, executes mathematical integrity verification,
and provides live database tampering simulation to prove forensic detection capabilities.
"""

import csv
import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Optional
from audit.audit_logger import get_audit_logger
from audit.audit_verifier import AuditVerificationReport, get_audit_verifier
from auth.session_manager import UserSession
from config.settings import THEME
from database.database import get_db
from security.access_control import VaultAction
from security.policy_engine import get_policy_engine
from ui.components import PolicyDecisionDialog, create_badge


class AuditView(tk.Frame):
    """Forensic interface for the tamper-evident audit ledger."""

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
        self.verifier = get_audit_verifier()
        self.audit_logger = get_audit_logger()
        self.policy = get_policy_engine()

        self._build_ui()
        self._refresh_table()

    def _build_ui(self):
        # Top Header
        top = tk.Frame(self, bg=THEME["bg_dark"])
        top.pack(fill="x", padx=24, pady=(20, 16))

        title_frame = tk.Frame(top, bg=THEME["bg_dark"])
        title_frame.pack(side="left")

        tk.Label(
            title_frame,
            text="TAMPER-EVIDENT AUDIT & FORENSICS",
            font=("Segoe UI", 16, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_dark"],
        ).pack(anchor="w")

        tk.Label(
            title_frame,
            text="Cryptographically Chained SHA-256 Security Ledger — Zero Historical Mutation Tolerated",
            font=("Segoe UI", 9),
            fg=THEME["text_secondary"],
            bg=THEME["bg_dark"],
        ).pack(anchor="w")

        # Top Action Buttons
        btn_box = tk.Frame(top, bg=THEME["bg_dark"])
        btn_box.pack(side="right")

        btn_verify = tk.Button(
            btn_box,
            text="🔍 Verify Audit Integrity",
            command=self._handle_verify_integrity,
            bg=THEME["success"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            padx=14,
            pady=8,
        )
        btn_verify.pack(side="left", padx=4)

        btn_tamper = tk.Button(
            btn_box,
            text="⚡ Simulate Record Tampering",
            command=self._handle_simulate_tampering,
            bg=THEME["warning"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            padx=14,
            pady=8,
        )
        btn_tamper.pack(side="left", padx=4)

        btn_repair = tk.Button(
            btn_box,
            text="🛠️ Re-Anchor Chain",
            command=self._handle_repair_chain,
            bg=THEME["bg_surface"],
            fg=THEME["text_primary"],
            font=("Segoe UI", 9),
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=8,
        )
        btn_repair.pack(side="left", padx=4)

        btn_export = tk.Button(
            btn_box,
            text="📥 Export CSV",
            command=self._handle_export_csv,
            bg=THEME["bg_surface"],
            fg=THEME["text_secondary"],
            font=("Segoe UI", 9),
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=8,
        )
        btn_export.pack(side="left", padx=4)

        # Integrity Status Card / Banner
        self.status_card = tk.Frame(
            self,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=16,
            pady=12,
        )
        self.status_card.pack(fill="x", padx=24, pady=(0, 16))

        self.lbl_status_icon = tk.Label(
            self.status_card,
            text="🔗",
            font=("Segoe UI", 14),
            bg=THEME["bg_card"],
            fg=THEME["accent_cyan"],
        )
        self.lbl_status_icon.pack(side="left", padx=(0, 10))

        self.lbl_status_text = tk.Label(
            self.status_card,
            text="Ledger Ready. Run verification to compute cryptographic proof across all historical blocks.",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_card"],
        )
        self.lbl_status_text.pack(side="left")

        # Main Table Card
        table_card = tk.Frame(
            self,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=16,
            pady=16,
        )
        table_card.pack(fill="both", expand=True, padx=24, pady=(0, 16))

        columns = (
            "id",
            "timestamp",
            "event_type",
            "username",
            "action",
            "resource",
            "status",
            "prev_hash",
            "curr_hash",
        )
        self.tree = ttk.Treeview(
            table_card,
            columns=columns,
            show="headings",
            selectmode="browse",
            height=10,
        )

        self.tree.heading("id", text="Block #")
        self.tree.heading("timestamp", text="Timestamp (UTC)")
        self.tree.heading("event_type", text="Event Type")
        self.tree.heading("username", text="Operator")
        self.tree.heading("action", text="Action Performed")
        self.tree.heading("resource", text="Resource")
        self.tree.heading("status", text="Status")
        self.tree.heading("prev_hash", text="Previous Hash (SHA-256)")
        self.tree.heading("curr_hash", text="Block Hash (SHA-256)")

        self.tree.column("id", width=55, anchor="center")
        self.tree.column("timestamp", width=135)
        self.tree.column("event_type", width=115)
        self.tree.column("username", width=85, anchor="center")
        self.tree.column("action", width=175)
        self.tree.column("resource", width=110)
        self.tree.column("status", width=75, anchor="center")
        self.tree.column("prev_hash", width=140)
        self.tree.column("curr_hash", width=140)

        scrollbar = ttk.Scrollbar(table_card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self._on_select_record)

        # Bottom Forensic Block Inspector
        self.inspector_card = tk.Frame(
            self,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=16,
            pady=12,
        )
        self.inspector_card.pack(fill="x", padx=24, pady=(0, 20))

        tk.Label(
            self.inspector_card,
            text="BLOCK CRYPTOGRAPHIC INSPECTOR",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["accent_cyan"],
            bg=THEME["bg_card"],
        ).pack(anchor="w", pady=(0, 6))

        self.txt_inspector = tk.Text(
            self.inspector_card,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=("Consolas", 8),
            height=4,
            relief="solid",
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=8,
            pady=6,
        )
        self.txt_inspector.pack(fill="x")
        self.txt_inspector.insert(
            "1.0", "Select any block above to inspect full 256-bit hashes and JSON metadata."
        )
        self.txt_inspector.config(state="disabled")

    def _refresh_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        records = self.db.fetch_all("SELECT * FROM audit_log ORDER BY id DESC;")
        for r in records:
            self.tree.insert(
                "",
                "end",
                values=(
                    f"#{r['id']}",
                    r["timestamp"][:19].replace("T", " "),
                    r["event_type"],
                    r["username"],
                    r["action"],
                    f"{r['resource_type']}:{r['resource_id'] or ''}",
                    r["status"],
                    r["previous_hash"][:16] + "...",
                    r["current_hash"][:16] + "...",
                ),
            )

    def _on_select_record(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        row_vals = self.tree.item(selection[0], "values")
        rec_id_str = row_vals[0].replace("#", "")

        row = self.db.fetch_one("SELECT * FROM audit_log WHERE id = ?;", (int(rec_id_str),))
        if not row:
            return

        detail_pretty = row["details"]
        try:
            detail_pretty = json.dumps(json.loads(row["details"]), indent=2)
        except Exception:
            pass

        info_text = (
            f"BLOCK ID: {row['id']}  |  EVENT: {row['event_type']}  |  OPERATOR: {row['username']}  |  STATUS: {row['status']}\n"
            f"FULL PREVIOUS HASH: {row['previous_hash']}\n"
            f"FULL CURRENT HASH:  {row['current_hash']}\n"
            f"METADATA PAYLOAD:\n{detail_pretty}"
        )

        self.txt_inspector.config(state="normal")
        self.txt_inspector.delete("1.0", tk.END)
        self.txt_inspector.insert("1.0", info_text)
        self.txt_inspector.config(state="disabled")

    def _handle_verify_integrity(self):
        """Verifies the complete audit chain and updates the status banner."""
        decision = self.policy.evaluate(self.session, VaultAction.AUDIT_VERIFY)
        if not decision.is_permitted:
            PolicyDecisionDialog(self, decision)
            return

        report = self.verifier.verify_integrity()

        if report.is_valid:
            self.status_card.config(bg=THEME["success_bg"])
            self.lbl_status_icon.config(text="✓", bg=THEME["success_bg"], fg="#a7f3d0")
            self.lbl_status_text.config(
                text=(
                    f"CRYPTOGRAPHIC AUDIT CHAIN INTACT: Verified {report.verified_records} of "
                    f"{report.total_records} blocks. No modification detected."
                ),
                bg=THEME["success_bg"],
                fg="#a7f3d0",
            )
            messagebox.showinfo(
                "Audit Verification Successful",
                f"Status: 100% VALID\n\n"
                f"Total Blocks Scanned: {report.total_records}\n"
                f"Cryptographically Verified: {report.verified_records}\n"
                f"Compromised Blocks: 0\n\n"
                f"Head Hash: {report.details.get('head_hash', 'N/A')}",
            )
        else:
            self.status_card.config(bg=THEME["danger_bg"])
            self.lbl_status_icon.config(text="🚨", bg=THEME["danger_bg"], fg="#fca5a5")
            self.lbl_status_text.config(
                text=(
                    f"ALERT: TAMPERING DETECTED AT BLOCK #{report.compromised_record_id}! "
                    f"{report.error_message}"
                ),
                bg=THEME["danger_bg"],
                fg="#fca5a5",
            )
            messagebox.showerror(
                "CRITICAL: AUDIT CHAIN TAMPERING DETECTED",
                f"The cryptographic hash chain has been VIOLATED!\n\n"
                f"Violation Type: {report.error_type}\n"
                f"Compromised Block ID: #{report.compromised_record_id}\n\n"
                f"Forensic Detail: {report.error_message}\n\n"
                f"The database records were altered outside of the authorized application layer.",
            )

    def _handle_simulate_tampering(self):
        """Allows user to tamper with a selected block to test forensic detection."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo(
                "Select Block",
                "Please select an audit block from the table that you wish to tamper with.",
            )
            return

        row_vals = self.tree.item(selection[0], "values")
        rec_id = int(row_vals[0].replace("#", ""))

        confirm = messagebox.askyesno(
            "Simulate Database Tampering",
            f"You are about to simulate an adversary attacking the SQLite database directly.\n\n"
            f"We will modify the action string of Block #{rec_id} to 'UNAUTHORIZED_DATA_EXFILTRATION' "
            f"WITHOUT updating the cryptographic SHA-256 hash.\n\n"
            f"Proceed with forensic tamper test?",
        )
        if not confirm:
            return

        self.verifier.simulate_tampering(rec_id, "UNAUTHORIZED_DATA_EXFILTRATION_TAMPERED")
        self._refresh_table()

        # Update banner warning
        self.status_card.config(bg=THEME["warning_bg"])
        self.lbl_status_icon.config(text="⚠️", bg=THEME["warning_bg"], fg="#fde68a")
        self.lbl_status_text.config(
            text=(
                f"Simulated database tampering applied to Block #{rec_id}! "
                f"Click 'Verify Audit Integrity' to observe real-time detection."
            ),
            bg=THEME["warning_bg"],
            fg="#fde68a",
        )

        messagebox.showwarning(
            "Tampering Injected",
            f"Block #{rec_id} has been modified directly in the SQLite table!\n\n"
            f"Now click 'Verify Audit Integrity' to demonstrate how the forensic engine "
            f"detects and pinpoints this exact corrupted block.",
        )

    def _handle_repair_chain(self):
        """Admin repair / re-anchor."""
        decision = self.policy.evaluate(self.session, VaultAction.AUDIT_VERIFY)
        if not decision.is_permitted or self.session.role != "Admin":
            PolicyDecisionDialog(self, decision)
            return

        confirm = messagebox.askyesno(
            "Re-Anchor Hash Chain",
            "This will sequentially recalculate hashes from genesis and append a formal "
            "SECURITY_REANCHOR audit block.\n\nProceed?",
        )
        if not confirm:
            return

        self.verifier.repair_and_reanchor_chain(self.session.username)
        self._refresh_table()
        self._handle_verify_integrity()

    def _handle_export_csv(self):
        """Exports the audit log to a CSV file."""
        save_path = filedialog.asksaveasfilename(
            title="Export Audit Ledger CSV",
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            initialfile="ayvault_audit_ledger.csv",
        )
        if not save_path:
            return

        records = self.db.fetch_all("SELECT * FROM audit_log ORDER BY id ASC;")
        if not records:
            messagebox.showinfo("Export Empty", "No audit records found to export.")
            return

        with open(save_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=records[0].keys())
            writer.writeheader()
            writer.writerows(records)

        messagebox.showinfo(
            "Export Complete",
            f"Exported {len(records)} audit records to:\n{save_path}",
        )
