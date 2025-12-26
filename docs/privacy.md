# Privacy and Redaction

AuthLens always redacts secrets in traces. The extension replaces values for these keys:

- code
- access_token
- id_token
- refresh_token
- client_secret
- assertion

The redacted value preserves only length and location context (query or fragment). Authorization headers are also redacted.

Redaction invariants:
- No raw code, tokens, client_secret, or Authorization header values are stored.
- Request bodies are not persisted; only the presence of specific field names may be recorded.
- Allowlist mode is enabled by default and requires user configuration before capture.
