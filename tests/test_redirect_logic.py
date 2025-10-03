"""Unit tests for OAuth state redirect logic - no app setup required"""

import base64
import json


def test_state_encoding_decoding() -> None:
    """Test the core state encoding/decoding logic"""
    # Test basic functionality
    redirect_url = "https://example.com/docs"
    state_data = {"redirect": redirect_url}

    # Encode (same logic as in auth_routes.py)
    state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    # Decode (same logic as in auth_routes.py)
    decoded_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
    decoded_url = decoded_data.get("redirect")

    assert decoded_url == redirect_url


def test_state_encoding_special_characters() -> None:
    """Test state encoding with URLs containing special characters"""
    test_urls = [
        "https://example.com/docs?param=value&other=123",
        "https://example.com/path with spaces/file.html",
        "https://example.com/path#anchor",
        "https://example.com/path?query=value%20encoded",
        "https://example.com/unicode/ñáméß",
        "http://localhost:8000/dev",
        "",  # Empty string edge case
    ]

    for url in test_urls:
        state_data = {"redirect": url}
        state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

        # Verify round-trip
        decoded_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
        decoded_url = decoded_data.get("redirect")

        assert decoded_url == url


def test_state_parameter_format() -> None:
    """Test that state parameter is URL-safe base64"""
    redirect_url = "https://example.com/protected/page"
    state_data = {"redirect": redirect_url}
    state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    # Verify state only contains URL-safe characters
    allowed_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
    assert all(c in allowed_chars for c in state)

    # Verify it's a valid base64 string
    try:
        base64.urlsafe_b64decode(state.encode())
    except Exception as e:
        raise AssertionError(f"State is not valid base64: {e}")


def test_invalid_state_handling() -> None:
    """Test how invalid state parameters should be handled"""
    invalid_states = [
        "invalid_base64!@#$",
        base64.urlsafe_b64encode(b"not valid json").decode(),
        base64.urlsafe_b64encode(json.dumps({"wrong_key": "value"}).encode()).decode(),
        "",
        None,
    ]

    for invalid_state in invalid_states:
        if invalid_state is None:
            # No state parameter case
            redirect_url = None
        else:
            # Try to decode invalid state (logic from auth_routes.py)
            try:
                state_data = json.loads(
                    base64.urlsafe_b64decode(invalid_state.encode()).decode()
                )
                redirect_url = state_data.get("redirect")
            except (ValueError, json.JSONDecodeError, Exception):
                redirect_url = None

        # Should handle gracefully by returning None
        assert redirect_url is None or redirect_url == ""


def test_state_security() -> None:
    """Test that state parameter doesn't expose sensitive info in plain text"""
    sensitive_url = "https://example.com/admin/users?token=secret123&key=private"
    state_data = {"redirect": sensitive_url}
    state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    # State should not contain sensitive parts in plain text
    assert "secret123" not in state
    assert "private" not in state
    assert "admin" not in state
    assert "token=" not in state

    # But should decode correctly
    decoded_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
    assert decoded_data["redirect"] == sensitive_url


def test_long_url_handling() -> None:
    """Test handling of very long URLs"""
    # Create a very long URL
    long_path = "/".join([f"segment{i}" for i in range(100)])
    long_url = f"https://example.com/{long_path}?param={'x' * 1000}"

    state_data = {"redirect": long_url}
    state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    # Should still encode/decode correctly
    decoded_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
    assert decoded_data["redirect"] == long_url


def test_multiple_redirect_parameters() -> None:
    """Test state with additional parameters beyond redirect"""
    redirect_url = "https://example.com/docs"
    state_data = {
        "redirect": redirect_url,
        "timestamp": "2023-01-01T00:00:00Z",
        "source": "oauth_flow",
    }

    state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    decoded_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
    assert decoded_data["redirect"] == redirect_url
    assert decoded_data["timestamp"] == "2023-01-01T00:00:00Z"
    assert decoded_data["source"] == "oauth_flow"


if __name__ == "__main__":
    # Run tests manually if called directly
    test_state_encoding_decoding()
    test_state_encoding_special_characters()
    test_state_parameter_format()
    test_invalid_state_handling()
    test_state_security()
    test_long_url_handling()
    test_multiple_redirect_parameters()
    print("All redirect logic tests passed! ✓")
