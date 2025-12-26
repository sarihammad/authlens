import { AuthTrace, LiveSummary } from "./trace";

const TRACE_KEY = (tabId: number) => `trace:${tabId}`;
const SUMMARY_KEY = (tabId: number) => `summary:${tabId}`;

export async function loadTrace(tabId: number): Promise<AuthTrace | null> {
  const res = await chrome.storage.session.get(TRACE_KEY(tabId));
  return (res[TRACE_KEY(tabId)] as AuthTrace) ?? null;
}

export async function saveTrace(trace: AuthTrace): Promise<void> {
  await chrome.storage.session.set({ [TRACE_KEY(trace.tabId)]: trace });
}

export async function clearTrace(tabId: number): Promise<void> {
  await chrome.storage.session.remove([TRACE_KEY(tabId), SUMMARY_KEY(tabId)]);
}

export async function saveSummary(summary: LiveSummary): Promise<void> {
  await chrome.storage.session.set({ [SUMMARY_KEY(summary.tabId)]: summary });
}

export async function loadSummary(tabId: number): Promise<LiveSummary | null> {
  const res = await chrome.storage.session.get(SUMMARY_KEY(tabId));
  return (res[SUMMARY_KEY(tabId)] as LiveSummary) ?? null;
}
