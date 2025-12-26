const SENSITIVE_KEYS = new Set([
  "code",
  "access_token",
  "id_token",
  "refresh_token",
  "client_secret",
  "assertion"
]);

function redactValue(v: string) {
  return `<redacted len=${v.length}>`;
}

export function redactUrl(raw: string): string {
  try {
    const u = new URL(raw);
    u.searchParams.forEach((val, key) => {
      if (SENSITIVE_KEYS.has(key)) u.searchParams.set(key, redactValue(val));
    });

    if (u.hash && u.hash.length > 1) {
      const frag = new URLSearchParams(u.hash.slice(1));
      frag.forEach((val, key) => {
        if (SENSITIVE_KEYS.has(key)) frag.set(key, redactValue(val));
      });
      u.hash = frag.toString() ? `#${frag.toString()}` : "";
    }
    return u.toString();
  } catch {
    return raw;
  }
}

export function normalizeHeaders(
  h?: chrome.webRequest.HttpHeader[]
): { name: string; value: string }[] | undefined {
  if (!h) return undefined;
  const out: { name: string; value: string }[] = [];
  for (const x of h) {
    if (!x.name) continue;
    if (x.name.toLowerCase() === "authorization" && x.value) {
      out.push({ name: x.name, value: "<redacted authorization>" });
    } else {
      out.push({ name: x.name, value: x.value ?? "" });
    }
  }
  return out;
}
