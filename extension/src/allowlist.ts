export function normalizeAllowlistInput(input: string): string[] {
  const raw = input
    .split(/\r?\n|,|\s+/)
    .map((entry) => entry.trim())
    .filter(Boolean);

  const out: string[] = [];
  for (const entry of raw) {
    try {
      if (entry.includes("://")) {
        out.push(new URL(entry).hostname.toLowerCase());
      } else {
        out.push(entry.toLowerCase());
      }
    } catch {
      out.push(entry.toLowerCase());
    }
  }

  return Array.from(new Set(out));
}

export function hostMatchesAllowlist(host: string, allowlist: string[]): boolean {
  const h = host.toLowerCase();
  for (const entry of allowlist) {
    if (!entry) continue;
    const e = entry.toLowerCase();
    if (e.startsWith("*.")) {
      const suffix = e.slice(2);
      if (h === suffix || h.endsWith(`.${suffix}`)) return true;
      continue;
    }
    if (h === e || h.endsWith(`.${e}`)) return true;
  }
  return false;
}
