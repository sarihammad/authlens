# AuthLens Rulebook

This rulebook tracks the findings the analyzer can emit in the MVP.

- STATE_MISSING: Callback includes code but no state.
- STATE_MISMATCH: Callback state does not match authorize state.
- NONCE_MISSING: OIDC authorize request missing nonce.
- PKCE_MISSING: Authorization request lacks code_challenge.
- PKCE_NOT_S256: Authorization request uses non-S256 code_challenge_method.
- PKCE_VERIFIER_MISSING: Token request missing code_verifier (best-effort).
- TOKEN_IN_QUERY: Token appears in URL query string.
- TOKEN_IN_FRAGMENT: Token appears in URL fragment.
- COOKIE_MISSING_SECURE: Session-like cookie lacks Secure.
- COOKIE_MISSING_HTTPONLY: Session-like cookie lacks HttpOnly.
- SAMESITE_NONE_WITHOUT_SECURE: SameSite=None without Secure.
- AUTHORIZE_BUT_NO_TOKEN: Authorize seen, but no token exchange observed.

Each finding includes a confidence level (HIGH/MED/LOW) to distinguish strong signals from heuristics.
