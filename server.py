import os
import re
import boto3
import hvac
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from mcp.server.fastmcp import FastMCP

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

# Initialize FastMCP server
mcp = FastMCP("MultiBackendSecretScannerSyncWithMock")

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
    """Safely retrieves a secret from Azure Key Vault with automatic mock fallback."""
    if FORCE_MOCK:
        return f"[MOCK FALLBACK] Azure OK: Retrieved simulated secret '{secret_name}' (16 chars)."

    target_url = vault_url or AZURE_VAULT_URL
    if not target_url:
        return "Azure Error: No Key Vault URL provided and AZURE_KEYVAULT_URL is empty. Set FORCE_MOCK_FALLBACK=true to simulate."

    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=target_url, credential=credential)
        retrieved_secret = client.get_secret(secret_name)
        return f"Azure OK: Retrieved '{secret_name}' ({len(retrieved_secret.value)} chars)."
    except Exception as e:
        # Fallback gracefully instead of breaking MCP execution loop
        return f"[AUTO-FALLBACK] Azure connection failed ({str(e)}). Simulated value for '{secret_name}': 'mock-azure-secret-val'."


@mcp.tool()
def fetch_aws_secret(secret_name: str, region_name: str = None) -> str:
    """Safely retrieves a secret from AWS Secrets Manager with automatic mock fallback."""
    if FORCE_MOCK:
        return f"[MOCK FALLBACK] AWS OK: Retrieved simulated secret '{secret_name}' (24 chars)."

    target_region = region_name or AWS_REGION
    try:
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager', region_name=target_region)
        response = client.get_secret_value(SecretId=secret_name)
        secret_content = response.get('SecretString', '')
        return f"AWS OK: Retrieved '{secret_name}' ({len(secret_content)} chars)."
    except Exception as e:
        return f"[AUTO-FALLBACK] AWS connection failed ({str(e)}). Simulated value for '{secret_name}': 'mock-aws-secret-val'."


@mcp.tool()
def fetch_hashicorp_secret(secret_path: str, mount_point: str = "secret", vault_url: str = None,
                           token: str = None) -> str:
    """Safely retrieves a key-value secret from HashiCorp Vault with automatic mock fallback."""
    if FORCE_MOCK:
        return f"[MOCK FALLBACK] HashiCorp Vault OK: Simulated keys ['api_key', 'db_pass'] for path '{secret_path}'."

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
        return f"[AUTO-FALLBACK] Vault unreachable ({str(e)}). Simulated keys for '{secret_path}': ['mock_key_1', 'mock_key_2']"


if __name__ == "__main__":
    mcp.run()
