# Privacy and Redaction

AuthLens always redacts secrets in traces. The extension replaces values for these keys:

- code
- access_token
- id_token
- refresh_token
- client_secret
- assertion

The redacted value preserves only length and location context (query or fragment). Authorization headers are also redacted.
