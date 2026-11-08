from app.services.auth import hash_password, verify_password
from app.services.chat import answer_chat, stream_chat
from app.services.storage import init_db


def setup_module():
    init_db()


def test_password_hashing_and_verification():
    secret = "SuperSecretPassword123!"
    hashed = hash_password(secret)
    assert hashed != secret
    assert verify_password(secret, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False


def test_chat_quick_count_answer():
    res = answer_chat("How many failed login events occurred?", owner_id="test-owner")
    assert "answer" in res
    assert "ConsoleLogin" in res["answer"]
    assert res["mode"] == "structured_query"


def test_chat_platform_help_answers():
    res = answer_chat("How to connect AWS and read-only permissions?", owner_id="test-owner")
    assert "answer" in res
    assert "CloudTrail" in res["answer"]
    assert res["mode"] == "platform_help"


def test_chat_streaming_generator_runs_smoothly():
    tokens = list(stream_chat("What does the risk score mean?", owner_id="test-owner"))
    full_text = "".join(tokens)
    assert len(tokens) > 5
    assert "Risk" in full_text or "Heuristic" in full_text or "Score" in full_text


def test_schemas_status_update_validation():
    from app.schemas import IncidentStatusUpdate, IncidentActionToggle
    import pytest
    from pydantic import ValidationError

    valid = IncidentStatusUpdate(status="RESOLVED")
    assert valid.status == "RESOLVED"

    with pytest.raises(ValidationError):
        IncidentStatusUpdate(status="UNKNOWN_STATUS")

    action = IncidentActionToggle(completed=True)
    assert action.completed is True


def test_login_email_normalization():
    from app.services.auth import login_account, register_account
    from uuid import uuid4

    unique_email = f"Analyst_{uuid4().hex[:8]}@Example.COM"
    pwd = "StrongSecurePassword2026!"
    register_account(unique_email, pwd, "Test Analyst")

    # Should succeed regardless of case casing when logging in
    res = login_account(unique_email.upper(), pwd)
    assert "access_token" in res
    assert res["user"]["email"] == unique_email.lower().strip()

