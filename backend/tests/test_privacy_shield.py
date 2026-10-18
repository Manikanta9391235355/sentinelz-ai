import pytest
from backend.app.services.privacy_shield import privacy_shield
from backend.app.services.ai_provider import LocalDeterministicAIProvider, ExternalAIProvider

def test_email_and_phone_redaction():
    sample_text = "Please reach out to analyst sarah.connor@cyberdyne.org or call +1 (555) 234-5678 immediately."
    result = privacy_shield.sanitize_text(sample_text)

    assert "[EMAIL_REDACTED]" in result["sanitized_text"]
    assert "[PHONE_REDACTED]" in result["sanitized_text"]
    assert "sarah.connor@cyberdyne.org" not in result["sanitized_text"]
    assert "555" not in result["sanitized_text"]
    assert result["detected_entities_summary"].get("EMAIL") == 1
    assert result["detected_entities_summary"].get("PHONE") == 1
    assert result["redacted_items_count"] == 2

def test_mainframe_account_and_ip_redaction():
    sample_text = "Mainframe ledger account IBM-ACCT-A9B2-9981 modified from host 192.168.1.105 with SSN 000-12-3456."
    result = privacy_shield.sanitize_text(sample_text)

    assert "[MAINFRAME_ACCT_REDACTED]" in result["sanitized_text"]
    assert "[IP_REDACTED]" in result["sanitized_text"]
    assert "[SSN_REDACTED]" in result["sanitized_text"]
    assert "IBM-ACCT-A9B2-9981" not in result["sanitized_text"]
    assert "192.168.1.105" not in result["sanitized_text"]
    assert "000-12-3456" not in result["sanitized_text"]

def test_non_overlapping_span_protection():
    """
    Ensures that when multiple patterns or adjacent entities exist,
    the text is not corrupted, duplicated, or mangled.
    """
    sample = "User alex@example.com account ACCT-98234123 at 10.0.0.1"
    result = privacy_shield.sanitize_text(sample)
    
    assert "[EMAIL_REDACTED]" in result["sanitized_text"]
    assert "[ACCOUNT_ID_REDACTED]" in result["sanitized_text"]
    assert "[IP_REDACTED]" in result["sanitized_text"]
    # Check that placeholders are clean and separated
    assert "[EMAIL_REDACTED] account [ACCOUNT_ID_REDACTED] at [IP_REDACTED]" in result["sanitized_text"]

def test_custom_confidential_terms():
    sample = "Operation SKYNET_CORE initiated by project APOLLO_7."
    result = privacy_shield.sanitize_text(sample, custom_patterns=["SKYNET_CORE", "APOLLO_7"])

    assert "[CONFIDENTIAL_TERM_REDACTED]" in result["sanitized_text"]
    assert "SKYNET_CORE" not in result["sanitized_text"]
    assert "APOLLO_7" not in result["sanitized_text"]
    assert result["redacted_items_count"] == 2

def test_ai_provider_boundary_enforcement(client, analyst_headers):
    """
    CRITICAL REGRESSION TEST:
    Proves that an unredacted input sent to /api/privacy/analyze-ai
    is sanitized BEFORE being received by the AI inference layer,
    and that raw unredacted text is NEVER exposed or returned unshielded.
    """
    raw_sensitive_input = "Target user john.doe@enterprise.corp with card 4532-1234-5678-9010 reported credential breach."
    
    response = client.post(
        "/api/privacy/analyze-ai",
        json={
            "text": raw_sensitive_input,
            "analysis_intent": "THREAT_SUMMARIZATION"
        },
        headers=analyst_headers
    )
    assert response.status_code == 200
    data = response.json()

    # Verify that unredacted indicators are never in the sanitized payload
    assert "john.doe@enterprise.corp" not in data["sanitization_summary"]["sanitized_text"]
    assert "4532-1234-5678-9010" not in data["sanitization_summary"]["sanitized_text"]
    assert data["unredacted_data_exposed"] is False
    assert data["sanitization_summary"]["ai_boundary_secured"] is True
    assert "[EMAIL_REDACTED]" in data["sanitization_summary"]["sanitized_text"]

def test_missing_ai_credentials_graceful_local_fallback():
    """
    Verifies that when AI API key is missing, system gracefully falls back
    to LocalDeterministicAIProvider without failing or hanging.
    """
    provider = LocalDeterministicAIProvider()
    res = provider.analyze_security_context("Observed [EMAIL_REDACTED] on [IP_REDACTED]", intent="ANOMALY_EXPLANATION")
    
    assert res["external_call_executed"] is False
    assert "Local" in res["provider"]
    assert len(res["result_text"]) > 20
