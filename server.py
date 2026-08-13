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

# Initialize FastMCP server
mcp = FastMCP("MultiBackendSecretScannerSync")

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
    """Safely retrieves a secret from Azure Key Vault using environment-level fallback settings."""
    target_url = vault_url or AZURE_VAULT_URL
    if not target_url:
        return "Azure Error: No Key Vault URL provided and AZURE_KEYVAULT_URL is empty."

    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=target_url, credential=credential)
        retrieved_secret = client.get_secret(secret_name)
        return f"Azure OK: Retrieved '{secret_name}' ({len(retrieved_secret.value)} chars)."
    except Exception as e:
        return f"Azure Error: {str(e)}"


@mcp.tool()
def fetch_aws_secret(secret_name: str, region_name: str = None) -> str:
    """Safely retrieves a secret from AWS Secrets Manager using system environment/CLI credentials."""
    target_region = region_name or AWS_REGION
    try:
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager', region_name=target_region)
        response = client.get_secret_value(SecretId=secret_name)
        secret_content = response.get('SecretString', '')
        return f"AWS OK: Retrieved '{secret_name}' ({len(secret_content)} chars)."
    except Exception as e:
        return f"AWS Error: {str(e)}"


@mcp.tool()
def fetch_hashicorp_secret(secret_path: str, mount_point: str = "secret", vault_url: str = None,
                           token: str = None) -> str:
    """Safely retrieves a key-value secret from HashiCorp Vault using environment-level fallbacks."""
    target_url = vault_url or HASHICORP_URL
    target_token = token or HASHICORP_TOKEN

    if not target_token:
        return "HashiCorp Error: Vault Token not found. Set VAULT_TOKEN environment variable."

    try:
        client = hvac.Client(url=target_url, token=target_token)
        read_response = client.secrets.kv.v2.read_secret_version(
            mount_point=mount_point,
            path=secret_path,
        )
        secret_data = read_response['data']['data']
        return f"HashiCorp Vault OK: Retrieved keys {list(secret_data.keys())} from path '{secret_path}'."
    except Exception as e:
        return f"HashiCorp Error: {str(e)}"


@mcp.tool()
def fetch_default_secret(secret_name_or_path: str) -> str:
    """Convenience proxy method executing a secret retrieval via the designated DEFAULT_SECRET_PROVIDER environment setting."""
    if DEFAULT_PROVIDER == "azure":
        return fetch_azure_secret(secret_name_or_path)
    elif DEFAULT_PROVIDER == "aws":
        return fetch_aws_secret(secret_name_or_path)
    elif DEFAULT_PROVIDER == "hashicorp":
        return fetch_hashicorp_secret(secret_name_or_path)
    else:
        return f"Configuration Error: Unknown environment provider '{DEFAULT_PROVIDER}'."


def run_local_tests():
    """Runs a quick CLI connectivity check against available environmental backend variables."""
    print("Evaluating environmental backend connectivity configurations...\n")
    print(f"Loaded Profile Settings:")
    print(f" - Primary Provider Default: {DEFAULT_PROVIDER}")
    print(f" - Azure URL Target: {AZURE_VAULT_URL or '[NOT SET]'}")
    print(f" - AWS Region Target: {AWS_REGION}")
    print(f" - HashiCorp Target: {HASHICORP_URL}\n")

    local_scan = scan_local_directory(os.getcwd())
    print(f"[Scanner Test]: Workspace scan result -> {local_scan}")

    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        print(f"[AWS Config Check]: Verified active session profile. Account ID: {identity.get('Account')}")
    except Exception as e:
        print(f"[AWS Config Check]: No active profile resolved or failed: {e}")

    try:
        credential = DefaultAzureCredential()
        token = credential.get_token("https://azure.net")
        print(f"[Azure Config Check]: Local default developer context token verified successfully.")
    except Exception as e:
        print(f"[Azure Config Check]: Developer profile skip/auth missing: {e}")

    try:
        client = hvac.Client(url=HASHICORP_URL)
        is_initialized = client.sys.is_initialized()
        print(f"[HashiCorp Config Check]: Endpoint reached -> {HASHICORP_URL} (Active init state: {is_initialized})")
    except Exception as e:
        print(f"[HashiCorp Config Check]: Endpoint unreachable -> {HASHICORP_URL} ({e})")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        run_local_tests()
    else:
        mcp.run()
