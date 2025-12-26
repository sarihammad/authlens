import { AuthTrace, TraceEvent, LiveSummary, Finding } from "./trace";
import { redactUrl, normalizeHeaders } from "./redact";
import { loadTrace, saveTrace, saveSummary } from "./storage";
import { isAuthUrl, liveFindingsFromUrl } from "./rules";
import { loadSettings, defaultSettings, Settings } from "./settings";
import { hostMatchesAllowlist } from "./allowlist";
import { parseUrlParams } from "./url";

const MAX_EVENTS = 500;
const FLOW_KEY = (tabId: number) => `flow:${tabId}`;
let cachedSettings: Settings | null = null;

type FlowState = {
  state?: string;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  responseType?: string;
  scope?: string;
  lastAuthorizeUrl?: string;
  lastAuthorizeAtMs?: number;
};

function nowMs() {
  return Date.now();
}

async function ensureTrace(tabId: number): Promise<AuthTrace> {
  const existing = await loadTrace(tabId);
  if (existing) return existing;
  const t: AuthTrace = {
    version: 1,
    tabId,
    startedAtMs: nowMs(),
    events: [],
    truncated: false,
    droppedEvents: 0
  };
  await saveTrace(t);
  return t;
}

function mergeFindings(a: Finding[], b: Finding[]): Finding[] {
  const key = (f: Finding) => `${f.id}:${f.evidence?.[0] ?? ""}`;
  const map = new Map<string, Finding>();
  for (const f of [...a, ...b]) map.set(key(f), f);
  return [...map.values()];
}

async function loadFlowState(tabId: number): Promise<FlowState | null> {
  const res = await chrome.storage.session.get(FLOW_KEY(tabId));
  return (res[FLOW_KEY(tabId)] as FlowState) ?? null;
}

async function saveFlowState(tabId: number, state: FlowState): Promise<void> {
  await chrome.storage.session.set({ [FLOW_KEY(tabId)]: state });
}

async function clearFlowState(tabId: number): Promise<void> {
  await chrome.storage.session.remove(FLOW_KEY(tabId));
}

function isAuthorizeUrl(url: string): boolean {
  return /\/(oauth\/authorize|authorize|oauth2\/authorize)\b/i.test(url);
}

async function getSettings(): Promise<Settings> {
  if (cachedSettings) return cachedSettings;
  cachedSettings = await loadSettings();
  return cachedSettings;
}

async function shouldRecordUrl(rawUrl: string): Promise<boolean> {
  const settings = await getSettings();
  if (!settings.onboarded) return false;
  if (!settings.allowlistEnabled) return true;
  if (settings.allowlist.length === 0) return false;
  try {
    const host = new URL(rawUrl).hostname;
    return hostMatchesAllowlist(host, settings.allowlist);
  } catch {
    return false;
  }
}

async function appendEvent(
  tabId: number,
  ev: TraceEvent,
  extraFindings: Finding[] = []
) {
  const trace = await ensureTrace(tabId);
  trace.events.push(ev);
  if (trace.events.length > MAX_EVENTS) {
    const dropped = trace.events.length - MAX_EVENTS;
    trace.events.splice(0, dropped);
    trace.truncated = true;
    trace.droppedEvents = (trace.droppedEvents ?? 0) + dropped;
  }
  await saveTrace(trace);

  const prev: LiveSummary =
    (await chrome.storage.session.get(`summary:${tabId}`))[`summary:${tabId}`] ?? {
      tabId,
      hasAuthSignals: false,
      findings: [],
      eventCount: 0
    };

  const hasAuthSignals = prev.hasAuthSignals || isAuthUrl(ev.url);
  const findings = mergeFindings(prev.findings, extraFindings);

  const summary: LiveSummary = {
    tabId,
    hasAuthSignals,
    findings,
    eventCount: trace.events.length,
    lastEventAtMs: Date.now(),
    traceTruncated: trace.truncated,
    droppedEvents: trace.droppedEvents
  };
  await saveSummary(summary);
}

chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (details.tabId < 0) return;
    if (!(await shouldRecordUrl(details.url))) return;
    const url = redactUrl(details.url);
    const params = parseUrlParams(details.url);
    const findings: Finding[] = [];
    const requestBodyKeys: string[] = [];

    if (details.requestBody?.formData) {
      for (const key of Object.keys(details.requestBody.formData)) {
        requestBodyKeys.push(key);
      }
    }

    const isTokenUrl = /\/(oauth\/token|token)\b/i.test(details.url);
    if (isTokenUrl && requestBodyKeys.length) {
      const hasCodeVerifier = requestBodyKeys.some(
        (k) => k.toLowerCase() === "code_verifier"
      );
      if (!hasCodeVerifier) {
        findings.push({
          id: "PKCE_VERIFIER_MISSING",
          severity: "MED",
          confidence: "MED",
          title: "Token request missing code_verifier",
          why: "Missing code_verifier prevents PKCE validation.",
          fix: "Include code_verifier in token requests for Authorization Code + PKCE.",
          evidence: [url]
        });
      }
    }

    if (isAuthorizeUrl(details.url)) {
      const state = params.query.get("state") ?? undefined;
      const nonce = params.query.get("nonce") ?? undefined;
      const codeChallenge = params.query.get("code_challenge") ?? undefined;
      const codeChallengeMethod =
        params.query.get("code_challenge_method") ?? undefined;
      const responseType = params.query.get("response_type") ?? undefined;
      const scope = params.query.get("scope") ?? undefined;

      const requiresNonce =
        (responseType && responseType.includes("id_token")) ||
        (scope && scope.split(/\s+/).includes("openid"));

      if (requiresNonce && !nonce) {
        findings.push({
          id: "NONCE_MISSING",
          severity: "HIGH",
          confidence: "HIGH",
          title: "Authorize request missing nonce",
          why: "OIDC requires nonce to prevent token replay.",
          fix: "Include a nonce for OIDC flows and validate it in the ID token.",
          evidence: [url]
        });
      }

      if (!codeChallenge) {
        findings.push({
          id: "PKCE_MISSING",
          severity: "HIGH",
          confidence: "HIGH",
          title: "Authorize request missing PKCE code_challenge",
          why: "PKCE mitigates code interception attacks for public clients.",
          fix: "Use Authorization Code + PKCE for public clients.",
          evidence: [url]
        });
      } else if (codeChallengeMethod && codeChallengeMethod.toLowerCase() !== "s256") {
        findings.push({
          id: "PKCE_NOT_S256",
          severity: "MED",
          confidence: "MED",
          title: "PKCE code_challenge_method is not S256",
          why: "S256 is the recommended PKCE method.",
          fix: "Prefer S256 for PKCE. Avoid 'plain' except in constrained environments.",
          evidence: [url]
        });
      }

      await saveFlowState(details.tabId, {
        state,
        nonce,
        codeChallenge,
        codeChallengeMethod,
        responseType,
        scope,
        lastAuthorizeUrl: url,
        lastAuthorizeAtMs: Date.now()
      });
    }

    const hasCode =
      params.query.has("code") || params.fragment.has("code");
    if (hasCode) {
      const callbackState =
        params.query.get("state") ?? params.fragment.get("state") ?? undefined;
      const flow = await loadFlowState(details.tabId);

      if (!callbackState) {
        findings.push({
          id: "STATE_MISSING",
          severity: "HIGH",
          confidence: "HIGH",
          title: "Callback includes code but no state",
          why: "State is required to prevent CSRF and code injection.",
          fix: "Always include and validate state to prevent CSRF/code injection.",
          evidence: [url]
        });
      } else if (flow?.state && callbackState !== flow.state) {
        findings.push({
          id: "STATE_MISMATCH",
          severity: "HIGH",
          confidence: "HIGH",
          title: "Callback state does not match authorize state",
          why: "Mismatched state indicates possible request forgery.",
          fix: "Reject callbacks with unexpected state values.",
          evidence: [url]
        });
      }
    }

    const ev: TraceEvent = {
      tMs: Date.now(),
      type: "HTTP",
      requestId: details.requestId,
      method: details.method,
      url,
      initiator: details.initiator ? redactUrl(details.initiator) : undefined,
      requestBodyKeys: requestBodyKeys.length ? requestBodyKeys : undefined
    };

    const urlFindings = isAuthUrl(details.url)
      ? liveFindingsFromUrl(details.url).map((f) => ({
          ...f,
          evidence: f.evidence?.map(redactUrl)
        }))
      : [];

    await appendEvent(details.tabId, ev, [...findings, ...urlFindings]);
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

chrome.webRequest.onHeadersReceived.addListener(
  async (details) => {
    if (details.tabId < 0) return;
    if (!(await shouldRecordUrl(details.url))) return;

    const ev: TraceEvent = {
      tMs: Date.now(),
      type: "HTTP",
      requestId: details.requestId,
      method: details.method,
      url: redactUrl(details.url),
      status: details.statusCode,
      responseHeaders: normalizeHeaders(details.responseHeaders)
    };

    await appendEvent(details.tabId, ev);
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

chrome.webNavigation?.onCommitted?.addListener(async (details) => {
  if (details.frameId !== 0) return;
  await clearFlowState(details.tabId);
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "sync") return;
  if (changes["settings:v1"]?.newValue) {
    cachedSettings = changes["settings:v1"].newValue as Settings;
  } else if (changes["settings:v1"]?.oldValue && !changes["settings:v1"]?.newValue) {
    cachedSettings = defaultSettings();
  }
});
