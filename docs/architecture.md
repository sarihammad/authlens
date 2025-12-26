# AuthLens Architecture

AuthLens is a monorepo with two main components:

- extension/: Chrome Extension (MV3, TypeScript) that captures OAuth/OIDC signals and exports a redacted trace.
- analyzer/: C++ CLI that ingests the trace and produces a findings report.

Data flow:
1) Extension observes network traffic and builds an Auth Trace per tab.
2) User exports the redacted trace JSON.
3) Analyzer reads the trace and emits a report JSON and a human summary.

The boundary between collection and analysis keeps browser permissions minimal and isolates heavier analysis logic.

Note: response headers are stored as a list of {name, value} pairs so multiple Set-Cookie headers are preserved.
Request bodies are not stored; the trace captures only field names (when available) for best-effort correlation.
Traces include a truncation flag and dropped event count if the event buffer overflows.
