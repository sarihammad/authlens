import { Finding } from "./trace";

export function isAuthUrl(url: string): boolean {
  return (
    /\/(oauth\/authorize|authorize|oauth2\/authorize|token|oauth\/token|userinfo)\b/i.test(
      url
    ) ||
    /[?&#](code|state|id_token|access_token)=/i.test(url) ||
    /\.well-known\/openid-configuration/i.test(url) ||
    /\.well-known\/jwks\.json/i.test(url)
  );
}

export function liveFindingsFromUrl(url: string): Finding[] {
  const findings: Finding[] = [];
  try {
    const u = new URL(url);
    const frag = new URLSearchParams(u.hash.startsWith("#") ? u.hash.slice(1) : "");

    if (
      u.searchParams.has("access_token") ||
      u.searchParams.has("id_token") ||
      u.searchParams.has("refresh_token")
    ) {
      findings.push({
        id: "TOKEN_IN_QUERY",
        severity: "HIGH",
        title: "Token appears in URL query string",
        fix: "Do not put tokens in URLs. Use Authorization header or secure cookies.",
        evidence: [url]
      });
    }

    if (frag.has("access_token") || frag.has("id_token")) {
      findings.push({
        id: "TOKEN_IN_FRAGMENT",
        severity: "MED",
        title: "Token appears in URL fragment",
        fix: "Avoid implicit/hybrid flows; use Authorization Code + PKCE.",
        evidence: [url]
      });
    }
  } catch {}
  return findings;
}
