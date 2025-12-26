# AuthLens

A Chrome Extension plus a C++ analyzer that detects OAuth/OIDC flow issues and exports a redacted trace for offline analysis.

## Demo

![AuthLens popup](docs/assets/screenshot-authlens.png)
![demo-authlens (1)](https://github.com/user-attachments/assets/66abc9cd-6605-4fdb-b814-819d1d9b0970)

## Architecture

```mermaid
flowchart LR
  Browser[Chrome Tab] -->|webRequest + webNavigation| ExtSW[Extension Service Worker]
  ExtSW -->|redacted trace JSON| Export[Export Trace]
  Export -->|authlens analyze| Analyzer[C++ Analyzer]
  Analyzer --> Report[Report JSON + Summary]
```

Tradeoffs:
- MV3 observer-only design avoids blocking requests but limits deep request-body inspection.
- Redaction in the extension reduces privacy risk but can obscure some diagnostics.
- Analyzer is isolated in C++ for performance and auditability, but adds an extra step.

## Privacy and permissions

Default posture:
- Allowlist mode is enabled by default and capture is disabled until the user configures domains.
- Host permissions remain broad to support dynamic allowlisting; onboarding makes this explicit.

Permission justification:
- `webRequest` + `webNavigation`: observe redirects and headers for auth flows.
- `tabs` + `storage`: per-tab trace state in session storage.
- `downloads`: export redacted traces on demand.

## Security and privacy

Threat model:
- Capturing sensitive OAuth artifacts in the trace.
- Leaking traces to unintended parties.
- Collecting more data than necessary.

Mitigations:
- Mandatory redaction of code, tokens, client_secret, and Authorization headers.
- No request body values stored; only field names when available.
- Allowlist required before capture and traces stored in session storage only.
- Export is user-initiated and produces a local file only.

Redaction invariants:
- We never store secrets in the trace.
- Redaction runs before any export.

See `docs/privacy.md` for details.

## Findings and confidence

Each finding includes a confidence level (HIGH/MED/LOW) to separate strong signals from heuristics.


## Testing

- Unit: URL parsing, redaction guarantees, allowlist matching, rule triggers.
- Integration: feed a known trace to the analyzer and compare to golden report.
- E2E: Not yet validated (real OAuth flow with a demo client).

## CI and releases

- CI builds the extension, runs unit tests, builds the analyzer, and runs the integration test.
- Release workflow builds artifacts for tagged releases (extension zip + analyzer binaries).

## Performance

Simple p50/p99 table (placeholders):

| Area | p50 | p99 |
| --- | --- | --- |
| Analyzer runtime | 3.54 ms | 6.73 ms |
| Popup render | 71.70 ms | 113.90 ms |

## Repo layout

- `extension/`: Chrome Extension
- `analyzer/`: C++ CLI analyzer
- `docs/`: Architecture, rulebook, and privacy notes
- `samples/`: Sanitized traces

## Build the extension

```
cd extension
npm install
npm run build
```

Load `extension/dist` via chrome://extensions.

## Build the analyzer

1) Download nlohmann/json single-header and save as `analyzer/third_party/json.hpp`.
2) Build:

```
cd analyzer
cmake -S . -B build
cmake --build build -j
```

Run:

```
./build/authlens analyze /path/to/trace.json --out report.json
```
