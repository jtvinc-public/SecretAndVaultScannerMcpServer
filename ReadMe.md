Description:

A minimal Local Secret Scanner & Vault Sync MCP server using Python and the high-level FastMCP SDK that requires only a single script. 
It scans a local path for accidental plain-text secrets via regex patterns. Supports Azure Key Vault, AWS Secrets Manager, and HashiCorp Vault.

Additional Remarks:

This code contains the ability to locally mock connectivity as a fallback.

Core Purposes of Local Mock FallbacksOffline Productivity

1. Allows developers to write, test, and debug AI agent integrations or local codebase scanning workflows on an airplane or during network outages without throwing continuous JSON-RPC or authentication exceptions.
2. Zero-Configuration Onboarding: Enables new contributors to spin up the MCP server instantly on their local machine without needing immediate access permissions, IAM roles, or active corporate cloud subscriptions.
3. Predictable Unit Testing: Provides static, deterministic mock values back to the LLM context during automated integration tests, preventing live credential leaks or rate-limiting spikes on remote secrets managers.
4. Graceful Degradation: Switches behavior transparently so that if a call to AWS Secrets Manager or HashiCorp Vault times out, the local runtime safely injects a dummy placeholder token instead of crashing the active agent session.