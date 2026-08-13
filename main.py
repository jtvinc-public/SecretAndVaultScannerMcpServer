import os
import re
from mcp.server.fastmcp import FastMCP
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import boto3
import hvac

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
def fetch_azure_secret(secret_name: str, vault_url: str) -> str:
    """Safely retrieves a secret from Azure Key Vault."""
    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=vault_url, credential=credential)
        retrieved_secret = client.get_secret(secret_name)
        return f"Azure OK: Retrieved '{secret_name}' ({len(retrieved_secret.value)} chars)."
    except Exception as e:
        return f"Azure Error: {str(e)}"

@mcp.tool()
def fetch_aws_secret(secret_name: str, region_name: str = "us-east-1") -> str:
    """Safely retrieves a secret from AWS Secrets Manager using local AWS CLI profile/creds."""
    try:
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager', region_name=region_name)
        response = client.get_secret_value(SecretId=secret_name)
        secret_content = response.get('SecretString', '')
        return f"AWS OK: Retrieved '{secret_name}' ({len(secret_content)} chars)."
    except Exception as e:
        return f"AWS Error: {str(e)}"

@mcp.tool()
def fetch_hashicorp_secret(secret_path: str, mount_point: str = "secret", vault_url: str = "http://localhost:8200", token: str = None) -> str:
    """Safely retrieves a key-value secret from HashiCorp Vault."""
    try:
        client = hvac.Client(url=vault_url, token=token or os.environ.get("VAULT_TOKEN"))
        # Read KV version 2 path
        read_response = client.secrets.kv.v2.read_secret_version(
            mount_point=mount_point,
            path=secret_path,
        )
        secret_data = read_response['data']['data']
        return f"HashiCorp Vault OK: Retrieved keys {list(secret_data.keys())} from path '{secret_path}'."
    except Exception as e:
        return f"HashiCorp Error: {str(e)}"

if __name__ == "__main__":
    mcp.run()
