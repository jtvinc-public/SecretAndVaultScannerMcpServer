import os
import re
from mcp.server.fastmcp import FastMCP
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Initialize FastMCP server
mcp = FastMCP("SecretAndVaultScannerMcpServer")

# Simple regex heuristics for common secrets (API keys, tokens)
SECRET_PATTERNS = {
    "Generic API Key": re.compile(r"(api[_-]?key|access[_-]?token)['\" ]*[:=]['\" ]([a-zA-Z0-9_\-]{20,})", re.I),
    "Azure Client Secret": re.compile(r"AZURE_CLIENT_SECRET['\" ]*[:=]['\" ]([a-zA-Z0-9\-_~.]{30,})", re.I)}


@mcp.tool()
def scan_local_directory(directory_path: str) -> str:
    """Scans a local directory path for accidentally hardcoded secrets."""
    findings = []
    if not os.path.exists(directory_path):
        return f"Error: Path {directory_path} does not exist."

    for root, _, files in os.walk(directory_path):
        # Skip virtual envs or hidden git directories
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
                        matches = pattern.findall(content)
                        if matches:
                            findings.append(f"[Found {name}] in {full_path}")
            except Exception:
                pass

    return "\n".join(findings) if findings else "No plaintext secrets detected."


@mcp.tool()
def fetch_azure_secret(secret_name: str, vault_url: str) -> str:
    """Safely retrieves a secure reference value from Azure Key Vault."""
    try:
        # DefaultAzureCredential handles local Azure CLI / environment auth seamlessly
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=vault_url, credential=credential)
        retrieved_secret = client.get_secret(secret_name)
        return f"Successfully retrieved secret '{secret_name}' (Value length: {len(retrieved_secret.value)} chars)."
    except Exception as e:
        return f"Failed to fetch from Azure Key Vault: {str(e)}"


if __name__ == "__main__":
    mcp.run()
