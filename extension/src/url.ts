export function parseUrlParams(rawUrl: string): {
  query: URLSearchParams;
  fragment: URLSearchParams;
} {
  try {
    const u = new URL(rawUrl);
    const query = u.searchParams;
    const fragment = new URLSearchParams(u.hash.startsWith("#") ? u.hash.slice(1) : "");
    return { query, fragment };
  } catch {
    return { query: new URLSearchParams(), fragment: new URLSearchParams() };
  }
}
