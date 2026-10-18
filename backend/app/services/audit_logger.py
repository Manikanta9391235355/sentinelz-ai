import json
import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from backend.app.models.all_models import AuditRecord

class AuditLoggerService:
    """
    Append-only audit logging service for SentinelZ AI.
    Records all security-relevant operational telemetry without exposing
    passwords, bearer tokens, private keys, or unredacted PII.
    """

    FORBIDDEN_KEYS = {
        "password", "hashed_password", "token", "access_token", "secret",
        "private_key", "api_key", "raw_text", "unredacted", "credit_card"
    }

    def sanitize_metadata(self, meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Strips any sensitive credentials or unredacted fields from audit metadata."""
        if not meta:
            return {}
        cleaned = {}
        for k, v in meta.items():
            if any(forbidden in k.lower() for forbidden in self.FORBIDDEN_KEYS):
                cleaned[k] = "[REDACTED_SECURITY_CONTROL]"
            elif isinstance(v, dict):
                cleaned[k] = self.sanitize_metadata(v)
            else:
                cleaned[k] = v
        return cleaned

    def log(
        self,
        db: Session,
        actor_id: str,
        actor_role: str,
        action: str,
        target_type: str,
        target_id: Optional[str] = None,
        outcome: str = "SUCCESS",
        client_ip: str = "127.0.0.1",
        request_id: Optional[str] = None,
        context_metadata: Optional[Dict[str, Any]] = None
    ) -> AuditRecord:
        """
        Appends an immutable audit entry to the database.
        """
        if not request_id:
            request_id = f"req_{uuid.uuid4().hex[:12]}"

        cleaned_meta = self.sanitize_metadata(context_metadata)

        record = AuditRecord(
            timestamp=datetime.utcnow(),
            actor_id=actor_id or "anonymous",
            actor_role=actor_role or "unauthenticated",
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id else None,
            outcome=outcome,
            request_id=request_id,
            client_ip=client_ip,
            context_metadata=json.dumps(cleaned_meta),
            created_at=datetime.utcnow()
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

audit_logger = AuditLoggerService()
