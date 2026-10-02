
"""
AY Vault - Encrypted Document Ingestion View
Uploads, hashes, and encrypts documents into the vault using AES-256-GCM.
Features live pre-ingestion cryptographic checksum calculations and policy pre-flight checks.
"""

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Optional
from auth.session_manager import UserSession
from config.settings import CLASSIFICATION_LEVELS, DEPARTMENTS, THEME
from documents.document_manager import get_document_manager
from security.access_control import VaultAction
from security.policy_engine import get_policy_engine
from security.security_utils import calculate_sha256_bytes, format_file_size
from ui.components import PolicyDecisionDialog


class UploadView(tk.Frame):
    """Document upload form with live cryptographic hashing and policy pre-flight check."""

    def __init__(
        self,
        parent: tk.Widget,
        session: UserSession,
        nav_callback: Callable[[str], None],
    ):
        super().__init__(parent, bg=THEME["bg_dark"])
        self.session = session
        self.nav_callback = nav_callback
        self.doc_mgr = get_document_manager()
        self.policy = get_policy_engine()

        self.selected_file_path: Optional[Path] = None
        self.raw_file_bytes: Optional[bytes] = None

        self._build_ui()

    def _build_ui(self):
        # Top Header
        top = tk.Frame(self, bg=THEME["bg_dark"])
        top.pack(fill="x", padx=24, pady=(20, 16))

        title_frame = tk.Frame(top, bg=THEME["bg_dark"])
        title_frame.pack(side="left")

        tk.Label(
            title_frame,
            text="ENCRYPTED DOCUMENT INGESTION",
            font=("Segoe UI", 16, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_dark"],
        ).pack(anchor="w")

        tk.Label(
            title_frame,
            text="Zero-Knowledge Ingest: All files are encrypted with AES-256-GCM before disk write.",
            font=("Segoe UI", 9),
            fg=THEME["text_secondary"],
            bg=THEME["bg_dark"],
        ).pack(anchor="w")

        # Two-column layout
        container = tk.Frame(self, bg=THEME["bg_dark"])
        container.pack(fill="both", expand=True, padx=24, pady=(0, 24))
        container.columnconfigure(0, weight=3)
        container.columnconfigure(1, weight=2)

        # Left Column: Ingest Form
        form_card = tk.Frame(
            container,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=20,
            pady=20,
        )
        form_card.grid(row=0, column=0, sticky="nsew", padx=(0, 12))

        # Title Field
        tk.Label(
            form_card,
            text="DOCUMENT TITLE *",
            font=("Segoe UI", 8, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        ).pack(anchor="w", pady=(0, 4))

        self.entry_title = tk.Entry(
            form_card,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            insertbackground=THEME["text_primary"],
            font=("Segoe UI", 10),
            relief="solid",
            highlightbackground=THEME["border"],
            highlightthickness=1,
        )
        self.entry_title.pack(fill="x", ipady=4, pady=(0, 14))

        # File Selection Picker
        tk.Label(
            form_card,
            text="SELECT FILE TO ENCRYPT *",
            font=("Segoe UI", 8, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        ).pack(anchor="w", pady=(0, 4))

        picker_frame = tk.Frame(form_card, bg=THEME["bg_card"])
        picker_frame.pack(fill="x", pady=(0, 14))

        self.entry_file_path = tk.Entry(
            picker_frame,
            bg=THEME["bg_input"],
            fg=THEME["text_muted"],
            font=("Segoe UI", 9),
            relief="solid",
            highlightbackground=THEME["border"],
            highlightthickness=1,
            state="readonly",
        )
        self.entry_file_path.pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 8))

        btn_browse = tk.Button(
            picker_frame,
            text="Browse File...",
            command=self._handle_browse_file,
            bg=THEME["bg_surface"],
            fg=THEME["text_primary"],
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=4,
        )
        btn_browse.pack(side="right")

        # Classification & Department Selectors (Row)
        meta_row = tk.Frame(form_card, bg=THEME["bg_card"])
        meta_row.pack(fill="x", pady=(0, 14))
        meta_row.columnconfigure((0, 1), weight=1)

        # Classification
        class_col = tk.Frame(meta_row, bg=THEME["bg_card"])
        class_col.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        tk.Label(
            class_col,
            text="CLASSIFICATION LEVEL *",
            font=("Segoe UI", 8, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        ).pack(anchor="w", pady=(0, 4))

        self.combo_class = ttk.Combobox(
            class_col,
            values=CLASSIFICATION_LEVELS,
            state="readonly",
        )
        # Default to user's clearance or UNRESTRICTED
        default_class = (
            self.session.clearance_level
            if self.session.clearance_level in CLASSIFICATION_LEVELS
            else "UNRESTRICTED"
        )
        self.combo_class.set(default_class)
        self.combo_class.pack(fill="x")
        self.combo_class.bind("<<ComboboxSelected>>", lambda e: self._update_preflight_check())

        # Department
        dept_col = tk.Frame(meta_row, bg=THEME["bg_card"])
        dept_col.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        tk.Label(
            dept_col,
            text="DEPARTMENT SILO *",
            font=("Segoe UI", 8, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        ).pack(anchor="w", pady=(0, 4))

        self.combo_dept = ttk.Combobox(
            dept_col,
            values=DEPARTMENTS,
            state="readonly",
        )
        self.combo_dept.set(
            self.session.department if self.session.department in DEPARTMENTS else "Security"
        )
        self.combo_dept.pack(fill="x")
        self.combo_dept.bind("<<ComboboxSelected>>", lambda e: self._update_preflight_check())

        # Description Field
        tk.Label(
            form_card,
            text="METADATA & OPERATIONAL DESCRIPTION",
            font=("Segoe UI", 8, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        ).pack(anchor="w", pady=(0, 4))

        self.txt_desc = tk.Text(
            form_card,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            insertbackground=THEME["text_primary"],
            font=("Segoe UI", 9),
            height=4,
            relief="solid",
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=8,
            pady=8,
        )
        self.txt_desc.pack(fill="x", pady=(0, 16))

        # Submit Action Button
        self.btn_submit = tk.Button(
            form_card,
            text="🔒 ENCRYPT & COMMIT TO VAULT",
            command=self._handle_submit,
            bg=THEME["primary"],
            activebackground=THEME["primary_hover"],
            fg="#ffffff",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            cursor="hand2",
            pady=10,
        )
        self.btn_submit.pack(fill="x")

        # Right Column: Cryptographic Pre-Flight Inspection Card
        preview_card = tk.Frame(
            container,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=20,
            pady=20,
        )
        preview_card.grid(row=0, column=1, sticky="nsew")

        tk.Label(
            preview_card,
            text="CRYPTOGRAPHIC PRE-FLIGHT INSPECTOR",
            font=("Segoe UI", 10, "bold"),
            fg=THEME["accent_cyan"],
            bg=THEME["bg_card"],
        ).pack(anchor="w", pady=(0, 12))

        # Live stats entries
        self.lbl_file_name = self._make_preview_row(preview_card, "Target Filename:", "No file selected")
        self.lbl_file_size = self._make_preview_row(preview_card, "File Size:", "0 B")
        self.lbl_sha256 = self._make_preview_row(preview_card, "Plaintext SHA-256:", "None")
        self.lbl_cipher_type = self._make_preview_row(preview_card, "Cipher Engine:", "AES-256-GCM Authenticated")
        self.lbl_key_derivation = self._make_preview_row(preview_card, "Key Management:", "Hardware Master / Envelope Nonce")

        # Policy Pre-Flight Status Badge
        tk.Label(
            preview_card,
            text="POLICY PRE-CHECK STATUS:",
            font=("Segoe UI", 8, "bold"),
            fg=THEME["text_muted"],
            bg=THEME["bg_card"],
        ).pack(anchor="w", pady=(16, 4))

        self.lbl_policy_status = tk.Label(
            preview_card,
            text="Awaiting File Selection...",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_surface"],
            padx=10,
            pady=8,
            anchor="w",
            wraplength=280,
            justify="left",
        )
        self.lbl_policy_status.pack(fill="x")

    def _make_preview_row(self, parent: tk.Widget, label_text: str, default_val: str) -> tk.Label:
        frame = tk.Frame(parent, bg=THEME["bg_card"])
        frame.pack(fill="x", pady=4)

        tk.Label(
            frame,
            text=label_text,
            font=("Segoe UI", 8, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
            width=18,
            anchor="w",
        ).pack(side="left")

        val_lbl = tk.Label(
            frame,
            text=default_val,
            font=("Segoe UI", 8),
            fg=THEME["text_primary"],
            bg=THEME["bg_card"],
            wraplength=180,
            justify="left",
            anchor="w",
        )
        val_lbl.pack(side="left", fill="x", expand=True)
        return val_lbl

    def _handle_browse_file(self):
        path_str = filedialog.askopenfilename(
            title="Select File for Vault Ingestion",
            filetypes=[
                ("All Supported Files", "*.*"),
                ("Documents (*.pdf, *.docx, *.txt, *.md)", "*.pdf;*.docx;*.txt;*.md"),
                ("Spreadsheets (*.xlsx, *.csv)", "*.xlsx;*.csv"),
            ],
        )
        if not path_str:
            return

        self.selected_file_path = Path(path_str)
        with open(self.selected_file_path, "rb") as f:
            self.raw_file_bytes = f.read()

        # Update input
        self.entry_file_path.config(state="normal")
        self.entry_file_path.delete(0, tk.END)
        self.entry_file_path.insert(0, str(self.selected_file_path))
        self.entry_file_path.config(state="readonly")

        # Auto-fill title if empty
        if not self.entry_title.get().strip():
            self.entry_title.insert(0, self.selected_file_path.stem.replace("_", " ").title())

        # Update live cryptographic preview
        sha256 = calculate_sha256_bytes(self.raw_file_bytes)
        self.lbl_file_name.config(text=self.selected_file_path.name)
        self.lbl_file_size.config(text=format_file_size(len(self.raw_file_bytes)))
        self.lbl_sha256.config(text=f"{sha256[:20]}...")

        self._update_preflight_check()

    def _update_preflight_check(self):
        classification = self.combo_class.get()
        department = self.combo_dept.get()

        sim_res = {
            "classification_level": classification,
            "department": department,
            "owner_id": self.session.user_id,
        }
        dec = self.policy.evaluate(
            self.session,
            VaultAction.DOC_WRITE,
            resource=sim_res,
            log_denial=False,
        )

        if dec.is_permitted:
            self.lbl_policy_status.config(
                text="✓ Policy Permits Ingestion (Clearance & Department Valid)",
                fg="#a7f3d0",
                bg=THEME["success_bg"],
            )
        else:
            self.lbl_policy_status.config(
                text=f"⚠️ Access Denied: {dec.reason}",
                fg="#fca5a5",
                bg=THEME["danger_bg"],
            )

    def _handle_submit(self):
        title = self.entry_title.get().strip()
        if not title:
            messagebox.showerror("Validation Error", "Document title is required.")
            return

        if not self.raw_file_bytes or not self.selected_file_path:
            messagebox.showerror("Validation Error", "Please select a file to encrypt.")
            return

        classification = self.combo_class.get()
        department = self.combo_dept.get()
        description = self.txt_desc.get("1.0", tk.END).strip()

        doc_record, decision = self.doc_mgr.upload_document(
            title=title,
            original_filename=self.selected_file_path.name,
            raw_bytes=self.raw_file_bytes,
            classification_level=classification,
            department=department,
            description=description,
            session=self.session,
        )

        if not decision.is_permitted or not doc_record:
            PolicyDecisionDialog(self, decision)
            return

        # Show cryptographic receipt
        messagebox.showinfo(
            "Cryptographic Ingest Complete",
            f"Document successfully secured in offline vault!\n\n"
            f"Document ID: {doc_record['id']}\n"
            f"Stored File: {doc_record['stored_filename']} (Encrypted AES-256-GCM)\n"
            f"Plaintext SHA-256: {doc_record['plaintext_sha256']}\n"
            f"Ciphertext SHA-256: {doc_record['ciphertext_sha256']}\n\n"
            f"Immutable audit record appended to cryptographic ledger.",
        )

        # Navigate back to vault explorer
        self.nav_callback("documents")
