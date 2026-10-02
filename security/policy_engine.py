"""
AY Vault - Central Security Policy Engine
Evaluates multilevel security (Bell-LaPadula MLS), role-based permissions,
and departmental compartmentalization before any sensitive action.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from auth.session_manager import UserSession
from audit.audit_logger import get_audit_logger
from config.settings import CLASSIFICATION_RANK, ROLE_ADMIN, ROLE_MANAGER
from security.access_control import VaultAction, has_role_permission, is_clearance_sufficient


@dataclass
class PolicyDecision:
    """Represents a deterministic authorization outcome."""
    is_permitted: bool
    decision_code: str
    reason: str
    rule_name: str
    evaluated_at: str
    context: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "permitted": self.is_permitted,
            "decision_code": self.decision_code,
            "reason": self.reason,
            "rule_name": self.rule_name,
            "evaluated_at": self.evaluated_at,
            "context": self.context,
        }


class PolicyEngine:
    """
    Central Authorization Engine.
    All system actions must query evaluate() prior to execution.
    """

    def __init__(self):
        self.audit_logger = get_audit_logger()

    def evaluate(
        self,
        session: Optional[UserSession],
        action: VaultAction,
        resource: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        log_denial: bool = True,
    ) -> PolicyDecision:
        """
        Evaluates authorization policy for the given subject, action, and resource.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        ctx = context or {}

        # Rule 1: Authentication Requirement
        if not session or session.is_expired():
            decision = PolicyDecision(
                is_permitted=False,
                decision_code="DENY_UNAUTHENTICATED",
                reason="Operation rejected: Active authenticated session required.",
                rule_name="POL_001_AUTHENTICATION_GATE",
                evaluated_at=now_iso,
                context=ctx,
            )
            return self._finalize(decision, session, action, resource, log_denial)

        user_role = session.role
        user_clearance = session.clearance_level
        user_dept = session.department

        # Rule 2: Role Baseline Permission
        if not has_role_permission(user_role, action):
            decision = PolicyDecision(
                is_permitted=False,
                decision_code="DENY_ROLE_CAPABILITY_MISSING",
                reason=f"Role '{user_role}' lacks baseline capability for '{action.value}'.",
                rule_name="POL_002_RBAC_BASELINE",
                evaluated_at=now_iso,
                context={"role": user_role, "action": action.value},
            )
            return self._finalize(decision, session, action, resource, log_denial)

        # Rule 3: Document-Specific MLS & Compartmentalization
        if resource and action in (
            VaultAction.DOC_READ,
            VaultAction.DOC_DOWNLOAD,
            VaultAction.DOC_WRITE,
            VaultAction.DOC_DELETE,
            VaultAction.DOC_CHANGE_PERM,
        ):
            doc_classification = resource.get("classification_level", "UNRESTRICTED")
            doc_dept = resource.get("department", "")
            doc_owner_id = resource.get("owner_id")

            # 3a. Bell-LaPadula MLS: Simple Security Property (No Read Up)
            if not is_clearance_sufficient(user_clearance, doc_classification):
                u_rank = CLASSIFICATION_RANK.get(user_clearance, 0)
                d_rank = CLASSIFICATION_RANK.get(doc_classification, 999)
                decision = PolicyDecision(
                    is_permitted=False,
                    decision_code="DENY_INSUFFICIENT_CLEARANCE",
                    reason=(
                        f"Access Denied by MLS Policy: User clearance '{user_clearance}' (Rank {u_rank}) "
                        f"is below document classification '{doc_classification}' (Rank {d_rank})."
                    ),
                    rule_name="POL_003_MLS_NO_READ_UP",
                    evaluated_at=now_iso,
                    context={
                        "user_clearance": user_clearance,
                        "doc_classification": doc_classification,
                    },
                )
                return self._finalize(decision, session, action, resource, log_denial)

            # 3b. Department Compartmentalization (Need-to-Know)
            # Admins or Executive clearance bypass departmental silo; others must match
            if user_role != ROLE_ADMIN and user_dept != "Executive":
                if doc_dept and doc_dept != user_dept:
                    decision = PolicyDecision(
                        is_permitted=False,
                        decision_code="DENY_DEPARTMENT_COMPARTMENTALIZATION",
                        reason=(
                            f"Compartmentalization Violation: Document restricted to '{doc_dept}' department. "
                            f"User belongs to '{user_dept}'."
                        ),
                        rule_name="POL_004_DEPARTMENT_SILO",
                        evaluated_at=now_iso,
                        context={"user_dept": user_dept, "doc_dept": doc_dept},
                    )
                    return self._finalize(decision, session, action, resource, log_denial)

            # 3c. Deletion Policy: Only Admins, or Managers who own the document
            if action == VaultAction.DOC_DELETE:
                if user_role != ROLE_ADMIN:
                    if not (user_role == ROLE_MANAGER and session.user_id == doc_owner_id):
                        decision = PolicyDecision(
                            is_permitted=False,
                            decision_code="DENY_DELETE_RESTRICTION",
                            reason="Only System Administrators or the document authoring Manager can delete documents.",
                            rule_name="POL_005_DELETION_AUTHORITY",
                            evaluated_at=now_iso,
                            context={"user_id": session.user_id, "doc_owner_id": doc_owner_id},
                        )
                        return self._finalize(decision, session, action, resource, log_denial)

        # Rule 4: Administrative-only modules
        if action in (
            VaultAction.USER_MANAGE,
            VaultAction.BACKUP_RESTORE,
            VaultAction.SECURITY_ADMIN,
            VaultAction.AUDIT_VERIFY,
        ):
            if user_role != ROLE_ADMIN:
                decision = PolicyDecision(
                    is_permitted=False,
                    decision_code="DENY_ADMIN_PRIVILEGE_REQUIRED",
                    reason=f"Action '{action.value}' is restricted exclusively to System Administrators.",
                    rule_name="POL_006_EXCLUSIVE_ADMIN",
                    evaluated_at=now_iso,
                    context={"role": user_role},
                )
                return self._finalize(decision, session, action, resource, log_denial)

        # All checks passed: Permit
        decision = PolicyDecision(
            is_permitted=True,
            decision_code="PERMIT_GRANTED",
            reason=f"Authorization granted: Subject satisfies all RBAC, MLS, and compartmental policies for '{action.value}'.",
            rule_name="POL_999_DEFAULT_ALLOW",
            evaluated_at=now_iso,
            context={"role": user_role, "clearance": user_clearance, "department": user_dept},
        )
        return decision

    def _finalize(
        self,
        decision: PolicyDecision,
        session: Optional[UserSession],
        action: VaultAction,
        resource: Optional[Dict[str, Any]],
        log_denial: bool,
    ) -> PolicyDecision:
        """Logs policy denials to tamper-evident audit ledger if enabled."""
        if not decision.is_permitted and log_denial:
            username = session.username if session else "ANONYMOUS"
            user_id = session.user_id if session else None
            res_id = str(resource.get("id")) if resource and "id" in resource else None
            res_type = "DOCUMENT" if resource else "SYSTEM"

            self.audit_logger.log_event(
                event_type="POLICY_DENIAL",
                action=f"DENIED_{action.value.upper()}",
                status="DENIED",
                user_id=user_id,
                username=username,
                resource_type=res_type,
                resource_id=res_id,
                details={
                    "rule": decision.rule_name,
                    "code": decision.decision_code,
                    "reason": decision.reason,
                    "evaluated_context": decision.context,
                },
            )
        return decision


_global_policy_engine = PolicyEngine()


def get_policy_engine() -> PolicyEngine:
    """Returns singleton PolicyEngine."""
    return _global_policy_engine
