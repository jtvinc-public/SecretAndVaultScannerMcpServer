import os
import tempfile
import server

def test_scan_local_directory_valid():
    """Test that the scanner successfully identifies a hardcoded generic API key in a temp file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file_path = os.path.join(tmpdir, "config.py")
        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write("api_key = 'super_secret_api_key_string_value_12345'\n")

        result = server.scan_local_directory(tmpdir)
        assert "Found Generic API Key" in result
        assert test_file_path in result

def test_scan_local_directory_clean():
    """Test that the scanner returns clean status when no secrets exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file_path = os.path.join(tmpdir, "safe.txt")
        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write("This file contains no sensitive tokens or keys.\n")

        result = server.scan_local_directory(tmpdir)
        assert result == "No plaintext secrets detected."

def test_scan_local_directory_nonexistent():
    """Test handling of an invalid directory path."""
    result = server.scan_local_directory("/non/existent/path/9999")
    assert "does not exist" in result

def test_fetch_azure_secret_force_mock(monkeypatch):
    """Test Azure fallback behavior when FORCE_MOCK_FALLBACK is enabled."""
    monkeypatch.setattr(server, "FORCE_MOCK", True)
    res = server.fetch_azure_secret("my-db-password")
    assert "[MOCK FALLBACK]" in res
    assert "my-db-password" in res

def test_fetch_aws_secret_force_mock(monkeypatch):
    """Test AWS fallback behavior when FORCE_MOCK_FALLBACK is enabled."""
    monkeypatch.setattr(server, "FORCE_MOCK", True)
    res = server.fetch_aws_secret("prod/rds/credentials")
    assert "[MOCK FALLBACK]" in res
    assert "prod/rds/credentials" in res

def test_fetch_hashicorp_secret_no_token_no_mock(monkeypatch):
    """Test HashiCorp error/fallback when token is completely omitted and mock is off."""
    monkeypatch.setattr(server, "FORCE_MOCK", False)
    monkeypatch.setattr(server, "HASHICORP_TOKEN", "")
    res = server.fetch_hashicorp_secret("secret/data/app")
    assert "HashiCorp Error: Token not found" in res
