"""
AY Vault - Document Vault Explorer View
Lists encrypted documents, enforces MLS / compartmentalization on demand,
and provides in-memory decryption previews, secure file export, and versioning.
"""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Optional
from auth.session_manager import UserSession
from config.settings import CLASSIFICATION_LEVELS, DEPARTMENTS, THEME
from documents.document_manager import get_document_manager
from documents.version_manager import get_version_manager
from security.access_control import VaultAction
from security.policy_engine import get_policy_engine
from security.security_utils import format_file_size
from ui.components import DocumentPreviewDialog, PolicyDecisionDialog, create_badge


class DocumentView(tk.Frame):
    """Document vault interface with policy enforcement and cryptographic inspection."""

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
        self.version_mgr = get_version_manager()
        self.policy = get_policy_engine()

        self._build_ui()
        self._refresh_documents()

    def _build_ui(self):
        # Top Header
        top = tk.Frame(self, bg=THEME["bg_dark"])
        top.pack(fill="x", padx=24, pady=(20, 16))

        title_frame = tk.Frame(top, bg=THEME["bg_dark"])
        title_frame.pack(side="left")

        tk.Label(
            title_frame,
            text="ENCRYPTED DOCUMENT VAULT",
            font=("Segoe UI", 16, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_dark"],
        ).pack(anchor="w")

        tk.Label(
            title_frame,
            text="AES-256-GCM Encrypted at Rest — Multilevel Bell-LaPadula Enforced",
            font=("Segoe UI", 9),
            fg=THEME["text_secondary"],
            bg=THEME["bg_dark"],
        ).pack(anchor="w")

        btn_new = tk.Button(
            top,
            text="➕ Ingest New Document",
            command=lambda: self.nav_callback("upload"),
            bg=THEME["primary"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            padx=14,
            pady=8,
        )
        btn_new.pack(side="right")

        # Filter & Search Bar
        filter_card = tk.Frame(
            self,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=16,
            pady=12,
        )
        filter_card.pack(fill="x", padx=24, pady=(0, 16))

        # Search
        tk.Label(
            filter_card,
            text="Search:",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        ).pack(side="left", padx=(0, 6))

        self.entry_search = tk.Entry(
            filter_card,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            insertbackground=THEME["text_primary"],
            font=("Segoe UI", 9),
            width=24,
            relief="solid",
            highlightbackground=THEME["border"],
            highlightthickness=1,
        )
        self.entry_search.pack(side="left", padx=(0, 16), ipady=3)
        self.entry_search.bind("<Return>", lambda e: self._refresh_documents())

        # Classification filter
        tk.Label(
            filter_card,
            text="Classification:",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        ).pack(side="left", padx=(0, 6))

        self.combo_class = ttk.Combobox(
            filter_card,
            values=["ALL"] + CLASSIFICATION_LEVELS,
            state="readonly",
            width=14,
        )
        self.combo_class.set("ALL")
        self.combo_class.pack(side="left", padx=(0, 16))
        self.combo_class.bind("<<ComboboxSelected>>", lambda e: self._refresh_documents())

        # Department filter
        tk.Label(
            filter_card,
            text="Department:",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        ).pack(side="left", padx=(0, 6))

        self.combo_dept = ttk.Combobox(
            filter_card,
            values=["ALL"] + DEPARTMENTS,
            state="readonly",
            width=14,
        )
        self.combo_dept.set("ALL")
        self.combo_dept.pack(side="left", padx=(0, 16))
        self.combo_dept.bind("<<ComboboxSelected>>", lambda e: self._refresh_documents())

        # Filter buttons
        btn_filter = tk.Button(
            filter_card,
            text="Filter",
            command=self._refresh_documents,
            bg=THEME["bg_surface"],
            fg=THEME["text_primary"],
            font=("Segoe UI", 8, "bold"),
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=3,
        )
        btn_filter.pack(side="left", padx=4)

        btn_reset = tk.Button(
            filter_card,
            text="Reset",
            command=self._reset_filters,
            bg=THEME["bg_surface"],
            fg=THEME["text_secondary"],
            font=("Segoe UI", 8),
            relief="flat",
            cursor="hand2",
            padx=10,
            pady=3,
        )
        btn_reset.pack(side="left", padx=4)

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

        # Documents Treeview
        columns = (
            "title",
            "classification",
            "department",
            "owner",
            "size",
            "version",
            "can_read",
            "can_download",
            "doc_id",
        )
        self.tree = ttk.Treeview(
            table_card,
            columns=columns,
            show="headings",
            selectmode="browse",
            height=12,
        )

        self.tree.heading("title", text="Document Title")
        self.tree.heading("classification", text="Classification")
        self.tree.heading("department", text="Department")
        self.tree.heading("owner", text="Author")
        self.tree.heading("size", text="Size")
        self.tree.heading("version", text="Ver")
        self.tree.heading("can_read", text="Read Auth")
        self.tree.heading("can_download", text="Export Auth")
        self.tree.heading("doc_id", text="Document UUID")

        self.tree.column("title", width=260)
        self.tree.column("classification", width=110, anchor="center")
        self.tree.column("department", width=95, anchor="center")
        self.tree.column("owner", width=85, anchor="center")
        self.tree.column("size", width=75, anchor="center")
        self.tree.column("version", width=45, anchor="center")
        self.tree.column("can_read", width=85, anchor="center")
        self.tree.column("can_download", width=85, anchor="center")
        self.tree.column("doc_id", width=180)

        # Scrollbar
        scrollbar = ttk.Scrollbar(table_card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", lambda e: self._handle_view_document())

        # Action Toolbar
        action_card = tk.Frame(
            self,
            bg=THEME["bg_card"],
            highlightbackground=THEME["border"],
            highlightthickness=1,
            padx=16,
            pady=12,
        )
        action_card.pack(fill="x", padx=24, pady=(0, 20))

        tk.Label(
            action_card,
            text="DOCUMENT ACTIONS:",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["text_secondary"],
            bg=THEME["bg_card"],
        ).pack(side="left", padx=(0, 12))

        btn_view = tk.Button(
            action_card,
            text="🔍 Inspect Decrypted Content",
            command=self._handle_view_document,
            bg=THEME["primary"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=6,
        )
        btn_view.pack(side="left", padx=4)

        btn_export = tk.Button(
            action_card,
            text="💾 Decrypt & Export to Disk",
            command=self._handle_export_document,
            bg=THEME["bg_surface"],
            fg=THEME["text_primary"],
            font=("Segoe UI", 9),
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=6,
        )
        btn_export.pack(side="left", padx=4)

        btn_rev = tk.Button(
            action_card,
            text="📑 Upload Revision Snapshot",
            command=self._handle_new_version,
            bg=THEME["bg_surface"],
            fg=THEME["text_primary"],
            font=("Segoe UI", 9),
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=6,
        )
        btn_rev.pack(side="left", padx=4)

        btn_inspect = tk.Button(
            action_card,
            text="🛡️ Policy Inspector",
            command=self._handle_inspect_policy,
            bg=THEME["bg_surface"],
            fg=THEME["accent_cyan"],
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=6,
        )
        btn_inspect.pack(side="left", padx=4)

        btn_del = tk.Button(
            action_card,
            text="🗑️ Delete",
            command=self._handle_delete_document,
            bg=THEME["bg_surface"],
            fg=THEME["danger"],
            font=("Segoe UI", 9),
            relief="flat",
            cursor="hand2",
            padx=12,
            pady=6,
        )
        btn_del.pack(side="right", padx=4)

    def _reset_filters(self):
        self.entry_search.delete(0, tk.END)
        self.combo_class.set("ALL")
        self.combo_dept.set("ALL")
        self._refresh_documents()

    def _get_selected_doc_id(self) -> Optional[str]:
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("Selection Required", "Please select a document from the table first.")
            return None
        values = self.tree.item(selection[0], "values")
        return values[8]  # doc_id column

    def _refresh_documents(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        search_query = self.entry_search.get().strip() or None
        classification = self.combo_class.get()
        department = self.combo_dept.get()

        docs = self.doc_mgr.list_documents(
            session=self.session,
            search_query=search_query,
            classification=classification,
            department=department,
        )

        for d in docs:
            read_status = "PERMITTED" if d["can_read"] else "DENIED"
            down_status = "PERMITTED" if d["can_download"] else "DENIED"

            self.tree.insert(
                "",
                "end",
                values=(
                    d["title"],
                    d["classification_level"],
                    d["department"],
                    d["owner_username"],
                    format_file_size(d["file_size_bytes"]),
                    f"v{d['version']}",
                    read_status,
                    down_status,
                    d["id"],
                ),
            )

    def _handle_view_document(self):
        doc_id = self._get_selected_doc_id()
        if not doc_id:
            return

        plaintext, doc, decision = self.doc_mgr.read_document_content(doc_id, self.session)

        if not decision.is_permitted:
            PolicyDecisionDialog(self, decision)
            return

        versions = self.version_mgr.get_versions(doc_id)
        DocumentPreviewDialog(self, doc, plaintext, versions)

    def _handle_export_document(self):
        doc_id = self._get_selected_doc_id()
        if not doc_id:
            return

        # Pre-check download policy before asking user for save location
        doc = self.doc_mgr.db.fetch_one("SELECT * FROM documents WHERE id = ?;", (doc_id,))
        if not doc:
            messagebox.showerror("Error", "Document not found.")
            return

        decision = self.policy.evaluate(self.session, VaultAction.DOC_DOWNLOAD, doc)
        if not decision.is_permitted:
            PolicyDecisionDialog(self, decision)
            return

        # Prompt for destination file
        save_path = filedialog.asksaveasfilename(
            title=f"Export Decrypted - {doc['original_filename']}",
            initialfile=doc["original_filename"],
        )
        if not save_path:
            return

        success, decision = self.doc_mgr.export_document(doc_id, save_path, self.session)
        if success:
            messagebox.showinfo(
                "Export Succeeded",
                f"Document successfully decrypted and exported to:\n{save_path}\n\n"
                f"Plaintext SHA-256 integrity verified:\n{doc['plaintext_sha256']}",
            )
        else:
            PolicyDecisionDialog(self, decision)

    def _handle_new_version(self):
        doc_id = self._get_selected_doc_id()
        if not doc_id:
            return

        doc = self.doc_mgr.db.fetch_one("SELECT * FROM documents WHERE id = ?;", (doc_id,))
        decision = self.policy.evaluate(self.session, VaultAction.DOC_WRITE, doc)
        if not decision.is_permitted:
            PolicyDecisionDialog(self, decision)
            return

        file_path = filedialog.askopenfilename(title="Select Replacement / Updated File")
        if not file_path:
            return

        # Prompt for change summary
        prompt_win = tk.Toplevel(self)
        prompt_win.title("Version Change Summary")
        prompt_win.geometry("400x200")
        prompt_win.configure(bg=THEME["bg_dark"])
        prompt_win.transient(self)
        prompt_win.grab_set()

        tk.Label(
            prompt_win,
            text=f"Enter Change Summary for v{doc['version'] + 1}:",
            font=("Segoe UI", 9, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_dark"],
        ).pack(padx=16, pady=(16, 8), anchor="w")

        entry_summary = tk.Entry(
            prompt_win,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            insertbackground=THEME["text_primary"],
            font=("Segoe UI", 9),
            relief="solid",
            highlightbackground=THEME["border"],
            highlightthickness=1,
        )
        entry_summary.pack(padx=16, fill="x", ipady=4, pady=(0, 16))
        entry_summary.insert(0, "Security patch and updated operational parameters.")

        def _do_upload_version():
            summary = entry_summary.get().strip() or "Version update."
            prompt_win.destroy()
            with open(file_path, "rb") as f:
                new_bytes = f.read()

            succ, dec = self.doc_mgr.add_document_version(
                doc_id, new_bytes, summary, self.session
            )
            if succ:
                messagebox.showinfo("Version Recorded", "New encrypted version snapshot stored.")
                self._refresh_documents()
            else:
                PolicyDecisionDialog(self, dec)

        tk.Button(
            prompt_win,
            text="Commit Revision Snapshot",
            command=_do_upload_version,
            bg=THEME["primary"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            cursor="hand2",
            pady=6,
        ).pack(padx=16, fill="x")

    def _handle_delete_document(self):
        doc_id = self._get_selected_doc_id()
        if not doc_id:
            return

        doc = self.doc_mgr.db.fetch_one("SELECT * FROM documents WHERE id = ?;", (doc_id,))
        decision = self.policy.evaluate(self.session, VaultAction.DOC_DELETE, doc)
        if not decision.is_permitted:
            PolicyDecisionDialog(self, decision)
            return

        confirm = messagebox.askyesno(
            "Confirm Deletion",
            f"Are you sure you want to soft-delete '{doc['title']}'?\n"
            "This action will be permanently recorded in the immutable audit ledger.",
        )
        if not confirm:
            return

        success, dec = self.doc_mgr.delete_document(doc_id, self.session)
        if success:
            messagebox.showinfo("Document Deleted", "Document has been deleted and recorded in audit log.")
            self._refresh_documents()
        else:
            PolicyDecisionDialog(self, dec)

    def _handle_inspect_policy(self):
        doc_id = self._get_selected_doc_id()
        if not doc_id:
            return

        doc = self.doc_mgr.db.fetch_one("SELECT * FROM documents WHERE id = ?;", (doc_id,))
        # Evaluate DOC_READ for inspection
        decision = self.policy.evaluate(
            self.session, VaultAction.DOC_READ, doc, log_denial=False
        )
        PolicyDecisionDialog(self, decision)
