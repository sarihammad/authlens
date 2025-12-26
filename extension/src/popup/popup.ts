import { loadSummary, loadTrace, clearTrace } from "../storage";

async function getActiveTabId(): Promise<number | null> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id ?? null;
}

function renderFindings(list: HTMLElement, findings: any[]) {
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
    list.appendChild(li);
  }
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
  const findingsEl = document.getElementById("findings")!;
  const exportBtn = document.getElementById("export") as HTMLButtonElement;
  const clearBtn = document.getElementById("clear") as HTMLButtonElement;

  if (tabId == null) {
    status.textContent = "No tab";
    return;
  }

  const summary = await loadSummary(tabId);
  status.textContent = summary?.hasAuthSignals ? "Auth detected" : "No auth";
  meta.textContent = `Tab ${tabId} - events: ${summary?.eventCount ?? 0}`;
  renderFindings(findingsEl, summary?.findings ?? []);

  exportBtn.onclick = () => exportTrace(tabId);
  clearBtn.onclick = async () => {
    await clearTrace(tabId);
    status.textContent = "Cleared";
    meta.textContent = `Tab ${tabId} - events: 0`;
    renderFindings(findingsEl, []);
  };
}

main().catch(console.error);
