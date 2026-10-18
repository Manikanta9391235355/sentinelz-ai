import re
import time
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

@dataclass
class MatchedSpan:
    entity_type: str
    placeholder: str
    start: int
    end: int
    matched_text: str

class PrivacyShieldService:
    """
    Dedicated PII detection and redaction engine for SentinelZ AI.
    Enforces the privacy boundary so that sensitive identifiers (emails, phone numbers,
    national IDs, account numbers, synthetic mainframe IDs, IP addresses) are sanitized
    prior to any storage, audit logging, or external AI evaluation.
    
    Includes non-overlapping span resolution to prevent text corruption.
    """

    # Compiled regex patterns for high-frequency sensitive attributes
    # Non-sensitive synthetic samples used in test/demo suites
    PATTERNS: Dict[str, Tuple[re.Pattern, str]] = {
        "EMAIL": (
            re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', re.IGNORECASE),
            "[EMAIL_REDACTED]"
        ),
        "PHONE": (
            re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
            "[PHONE_REDACTED]"
        ),
        "SSN": (
            re.compile(r'\b\d{3}[- ]\d{2}[- ]\d{4}\b'),
            "[SSN_REDACTED]"
        ),
        "MAINFRAME_ACCOUNT": (
            re.compile(r'\bIBM-ACCT-[A-Z0-9]{4}-[A-Z0-9]{4}\b', re.IGNORECASE),
            "[MAINFRAME_ACCT_REDACTED]"
        ),
        "ACCOUNT_ID": (
            re.compile(r'\b(?:ACCT|ACC|ACCOUNT)[#:\-\s]*([A-Z0-9]{6,20})\b', re.IGNORECASE),
            "[ACCOUNT_ID_REDACTED]"
        ),
        "CREDIT_CARD": (
            re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b'),
            "[PAYMENT_CARD_REDACTED]"
        ),
        "IP_ADDRESS": (
            re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            "[IP_REDACTED]"
        ),
    }

    def sanitize_text(
        self,
        raw_text: str,
        custom_patterns: List[str] = None,
        enable_account_masking: bool = True,
        enable_network_masking: bool = True
    ) -> Dict[str, Any]:
        """
        Scans raw_text for all configured sensitive entities, resolves overlapping matches,
        replaces each sensitive span with a typed placeholder, and outputs transformation stats.
        """
        start_time = time.perf_counter()
        if not raw_text:
            return {
                "original_char_count": 0,
                "sanitized_char_count": 0,
                "sanitized_text": "",
                "redacted_items_count": 0,
                "detected_entities_summary": {},
                "redacted_spans": [],
                "transformation_preview": "",
                "execution_time_ms": 0.0,
                "ai_boundary_secured": True
            }

        all_matches: List[MatchedSpan] = []

        # 1. Standard Patterns
        for entity_type, (regex, placeholder) in self.PATTERNS.items():
            if entity_type == "IP_ADDRESS" and not enable_network_masking:
                continue
            if entity_type in ("ACCOUNT_ID", "MAINFRAME_ACCOUNT", "CREDIT_CARD") and not enable_account_masking:
                continue

            for match in regex.finditer(raw_text):
                all_matches.append(MatchedSpan(
                    entity_type=entity_type,
                    placeholder=placeholder,
                    start=match.start(),
                    end=match.end(),
                    matched_text=match.group(0)
                ))

        # 2. Custom patterns
        if custom_patterns:
            for idx, pattern_str in enumerate(custom_patterns):
                if not pattern_str.strip():
                    continue
                try:
                    custom_regex = re.compile(re.escape(pattern_str.strip()), re.IGNORECASE)
                    for match in custom_regex.finditer(raw_text):
                        all_matches.append(MatchedSpan(
                            entity_type=f"CUSTOM_TERM_{idx+1}",
                            placeholder="[CONFIDENTIAL_TERM_REDACTED]",
                            start=match.start(),
                            end=match.end(),
                            matched_text=match.group(0)
                        ))
                except Exception:
                    continue

        # 3. Resolve Overlaps:
        # Sort matches primarily by start ascending, then length descending.
        # If two spans overlap, retain the longer span or earliest match.
        all_matches.sort(key=lambda m: (m.start, -(m.end - m.start)))
        non_overlapping_spans: List[MatchedSpan] = []
        last_end = -1

        for span in all_matches:
            if span.start >= last_end:
                non_overlapping_spans.append(span)
                last_end = span.end
            else:
                # Overlap detected: If current span is significantly longer, we could replace,
                # but standard greedy earlier match is safe and deterministic.
                continue

        # 4. Perform Replacement in Reverse Order
        # Working from highest index to lowest ensures start/end offsets remains valid!
        non_overlapping_spans.sort(key=lambda m: m.start, reverse=True)
        
        sanitized_chars = list(raw_text)
        summary_counts: Dict[str, int] = {}
        redacted_spans_meta: List[Dict[str, Any]] = []

        for span in non_overlapping_spans:
            # Replace slice
            sanitized_chars[span.start:span.end] = list(span.placeholder)
            summary_counts[span.entity_type] = summary_counts.get(span.entity_type, 0) + 1
            redacted_spans_meta.append({
                "entity_type": span.entity_type,
                "placeholder": span.placeholder,
                "start": span.start,
                "end": span.end,
                "char_length": span.end - span.start
            })

        sanitized_text = "".join(sanitized_chars)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Build transformation preview (compact diff showing first 200 chars or summary)
        preview = f"Sanitized {len(non_overlapping_spans)} entities across {len(raw_text)} chars."

        return {
            "original_char_count": len(raw_text),
            "sanitized_char_count": len(sanitized_text),
            "sanitized_text": sanitized_text,
            "redacted_items_count": len(non_overlapping_spans),
            "detected_entities_summary": summary_counts,
            "redacted_spans": redacted_spans_meta,
            "transformation_preview": preview,
            "execution_time_ms": round(elapsed_ms, 2),
            "ai_boundary_secured": True
        }

privacy_shield = PrivacyShieldService()
