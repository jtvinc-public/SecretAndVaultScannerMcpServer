import json
import os
import re
import sys
from mcp.server.fastmcp import FastMCP
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import boto3
import hvac

# Core configuration loaded safely from the host environment
# Set to azure, aws, or hashicorp to define your primary backend.
DEFAULT_PROVIDER = os.environ.get("DEFAULT_SECRET_PROVIDER", "azure").lower()
# The URI for your vault (e.g., https://azure.net).
AZURE_VAULT_URL = os.environ.get("AZURE_KEYVAULT_URL", "")
# The AWS region for Secrets Manager (e.g., us-east-1) See Boto3 Configuration.
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
# The local or remote URL for Vault (e.g., http://localhost:8200) hvac Documentation.
HASHICORP_URL = os.environ.get("VAULT_URL", "http://localhost:8200")
# The authentication token for accessing HashiCorp Vault.
HASHICORP_TOKEN = os.environ.get("VAULT_TOKEN", "")

# Toggle to force mock fallback mode globally (e.g. for offline work)
FORCE_MOCK = os.environ.get("FORCE_MOCK_FALLBACK", "false").lower() == "true"
MOCK_FILE_PATH = os.environ.get("MOCK_SECRETS_FILE", "mock_secrets.json")


def load_mock_dictionary() -> dict:
    """Loads the external mock data dictionary safely from a JSON file."""
    if os.path.exists(MOCK_FILE_PATH):
        try:
            with open(MOCK_FILE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Failed to parse {MOCK_FILE_PATH} ({e}). Using empty mock fallback.", file=sys.stderr)
    return {"azure": {}, "aws": {}, "hashicorp": {}}


MOCK_SECRET_DICTIONARY = load_mock_dictionary()

# Initialize FastMCP server
mcp = FastMCP("MultiBackendSecretScannerSyncWithExternalMock")

SECRET_PATTERNS = {
    "Generic API Key": re.compile(r"(api[_-]?key|access[_-]?token)['\" ]*[:=]['\" ]([a-zA-Z0-9_\-]{20,})", re.I),
    "AWS Access Key": re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", re.I)
}


@mcp.tool()
def scan_local_directory(directory_path: str) -> str:
    """Scans a local directory path for accidentally hardcoded secrets."""
    findings = []
    if not os.path.exists(directory_path):
        return f"Error: Path {directory_path} does not exist."

    for root, _, files in os.walk(directory_path):
        if ".git" in root or ".venv" in root or "node_modules" in root:
            continue
        for file in files:
            if file.endswith((".log", ".lock", ".png", ".jpg", ".zip")):
                continue
            full_path = os.path.join(root, file)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    for name, pattern in SECRET_PATTERNS.items():
                        if pattern.search(content):
                            findings.append(f"[Found {name}] in {full_path}")
            except Exception:
                pass

    return "\n".join(findings) if findings else "No plaintext secrets detected."


@mcp.tool()
def fetch_azure_secret(secret_name: str, vault_url: str = None) -> str:
    """Safely retrieves a secret from Azure Key Vault with external JSON mock lookup."""
    azure_mocks = MOCK_SECRET_DICTIONARY.get("azure", {})
    if FORCE_MOCK or secret_name in azure_mocks:
        val = azure_mocks.get(secret_name, f"simulated-val-for-{secret_name}")
        return f"[JSON MOCK] Azure OK: Retrieved '{secret_name}' ({len(str(val))} chars)."

    target_url = vault_url or AZURE_VAULT_URL
    if not target_url:
        return "Azure Error: No Key Vault URL provided and AZURE_KEYVAULT_URL is empty."

    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=target_url, credential=credential)
        retrieved_secret = client.get_secret(secret_name)
        return f"Azure OK: Retrieved '{secret_name}' ({len(retrieved_secret.value)} chars)."
    except Exception as e:
        return f"[AUTO-FALLBACK] Azure connection failed ({str(e)}). Simulated value for '{secret_name}': 'mock-azure-val'."


@mcp.tool()
def fetch_aws_secret(secret_name: str, region_name: str = None) -> str:
    """Safely retrieves a secret from AWS Secrets Manager with external JSON mock lookup."""
    aws_mocks = MOCK_SECRET_DICTIONARY.get("aws", {})
    if FORCE_MOCK or secret_name in aws_mocks:
        val = aws_mocks.get(secret_name, f"simulated-val-for-{secret_name}")
        return f"[JSON MOCK] AWS OK: Retrieved '{secret_name}' ({len(str(val))} chars)."

    target_region = region_name or AWS_REGION
    try:
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager', region_name=target_region)
        response = client.get_secret_value(SecretId=secret_name)
        secret_content = response.get('SecretString', '')
        return f"AWS OK: Retrieved '{secret_name}' ({len(secret_content)} chars)."
    except Exception as e:
        return f"[AUTO-FALLBACK] AWS connection failed ({str(e)}). Simulated value for '{secret_name}': 'mock-aws-val'."


@mcp.tool()
def fetch_hashicorp_secret(secret_path: str, mount_point: str = "secret", vault_url: str = None,
                           token: str = None) -> str:
    """Safely retrieves a key-value secret from HashiCorp Vault with external JSON mock lookup."""
    vault_mocks = MOCK_SECRET_DICTIONARY.get("hashicorp", {})
    if FORCE_MOCK or secret_path in vault_mocks:
        val = vault_mocks.get(secret_path, {"mock_key": "simulated-value"})
        return f"[JSON MOCK] HashiCorp Vault OK: Retrieved keys {list(val.keys() if isinstance(val, dict) else [])} for path '{secret_path}'."

    target_url = vault_url or HASHICORP_URL
    target_token = token or HASHICORP_TOKEN

    if not target_token:
        return "HashiCorp Error: Token not found. Set VAULT_TOKEN or enable FORCE_MOCK_FALLBACK=true."

    try:
        client = hvac.Client(url=target_url, token=target_token)
        read_response = client.secrets.kv.v2.read_secret_version(
            mount_point=mount_point,
            path=secret_path,
        )
        secret_data = read_response['data']['data']
        return f"HashiCorp Vault OK: Retrieved keys {list(secret_data.keys())} from path '{secret_path}'."
    except Exception as e:
        return f"[AUTO-FALLBACK] Vault unreachable ({str(e)}). Simulated keys for '{secret_path}': ['mock_key_1']"


if __name__ == "__main__":
    mcp.run()
