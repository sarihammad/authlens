import { loadSummary, loadTrace, clearTrace } from "../storage";
import { loadSettings } from "../settings";
import { Finding } from "../trace";

const renderStartMs = performance.now();

async function getActiveTabId(): Promise<number | null> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id ?? null;
}

function renderFindings(list: HTMLElement, findings: Finding[], onSelect: (f: Finding) => void) {
  list.innerHTML = "";
  if (!findings.length) {
    const li = document.createElement("li");
    li.textContent = "No findings yet.";
    list.appendChild(li);
    return;
  }
  for (const f of findings) {
    const li = document.createElement("li");
    li.textContent = `[${f.severity}] ${f.title}`;
    li.tabIndex = 0;
    li.onclick = () => onSelect(f);
    li.onkeydown = (e) => {
      if (e.key === "Enter" || e.key === " ") onSelect(f);
    };
    list.appendChild(li);
  }
}

function renderDetail(detail: HTMLElement, f: Finding | null) {
  const title = document.getElementById("detailTitle")!;
  const severity = document.getElementById("detailSeverity")!;
  const confidence = document.getElementById("detailConfidence")!;
  const why = document.getElementById("detailWhy")!;
  const fix = document.getElementById("detailFix")!;
  const evidence = document.getElementById("detailEvidence")!;

  if (!f) {
    detail.hidden = true;
    return;
  }

  title.textContent = f.title;
  severity.textContent = `Severity: ${f.severity}`;
  confidence.textContent = `Confidence: ${f.confidence ?? "MED"}`;
  why.textContent = f.why ? `Why it matters: ${f.why}` : "";
  fix.textContent = `Fix: ${f.fix}`;
  evidence.innerHTML = "";
  if (f.evidence?.length) {
    for (const ev of f.evidence) {
      const li = document.createElement("li");
      li.textContent = ev;
      evidence.appendChild(li);
    }
  } else {
    const li = document.createElement("li");
    li.textContent = "No evidence recorded.";
    evidence.appendChild(li);
  }

  detail.hidden = false;
}

async function exportTrace(tabId: number) {
  const trace = await loadTrace(tabId);
  if (!trace) return;

  const blob = new Blob([JSON.stringify(trace, null, 2)], {
    type: "application/json"
  });
  const url = URL.createObjectURL(blob);
  const filename = `authlens-trace-tab${tabId}-${new Date()
    .toISOString()
    .replace(/[:.]/g, "-")}.json`;

  await chrome.downloads.download({ url, filename, saveAs: true });
}

async function main() {
  const tabId = await getActiveTabId();
  const status = document.getElementById("status")!;
  const meta = document.getElementById("meta")!;
  const notice = document.getElementById("privacyNotice")!;
  const findingsEl = document.getElementById("findings")!;
  const exportBtn = document.getElementById("export") as HTMLButtonElement;
  const clearBtn = document.getElementById("clear") as HTMLButtonElement;
  const detail = document.getElementById("detail")!;
  const detailClose = document.getElementById("detailClose") as HTMLButtonElement;

  if (tabId == null) {
    status.textContent = "No tab";
    return;
  }

  let currentFindings: Finding[] = [];

  const render = async () => {
    const [summary, settings] = await Promise.all([
      loadSummary(tabId),
      loadSettings()
    ]);

    const needsAllowlist =
      settings.allowlistEnabled && settings.allowlist.length === 0;
    const notOnboarded = !settings.onboarded;

    notice.hidden = !(needsAllowlist || notOnboarded);
    exportBtn.disabled = needsAllowlist || notOnboarded;

    if (needsAllowlist || notOnboarded) {
      status.textContent = "Allowlist required";
      meta.textContent = "Open Options to configure domains.";
      renderFindings(findingsEl, [], () => undefined);
      renderDetail(detail, null);
      return;
    }

    const hasAuth = summary?.hasAuthSignals ?? false;
    status.textContent = hasAuth ? "Auth detected" : "No auth";

    const truncated = summary?.traceTruncated ? " (truncated)" : "";
    meta.textContent = `Tab ${tabId} - events: ${summary?.eventCount ?? 0}${truncated}`;

    currentFindings = summary?.findings ?? [];
    renderFindings(findingsEl, currentFindings, (f) => renderDetail(detail, f));
  };

  detailClose.onclick = () => renderDetail(detail, null);

  exportBtn.onclick = () => exportTrace(tabId);
  clearBtn.onclick = async () => {
    await clearTrace(tabId);
    await render();
  };

  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "session" && changes[`summary:${tabId}`]) {
      render().catch(console.error);
    }
    if (areaName === "sync" && changes["settings:v1"]) {
      render().catch(console.error);
    }
  });

  await render();
  const renderDurationMs = performance.now() - renderStartMs;
  console.info(`[AuthLens] popup initial render: ${renderDurationMs.toFixed(2)}ms`);
}

main().catch(console.error);
