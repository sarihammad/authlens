export type TraceEvent =
  | { tMs: number; type: "NAVIGATE"; url: string }
  | {
      tMs: number;
      type: "HTTP";
      requestId: string;
      method: string;
      url: string;
      initiator?: string;
      status?: number;
      requestBodyKeys?: string[];
      requestHeaders?: Record<string, string>;
      responseHeaders?: { name: string; value: string }[];
    };

export type AuthTrace = {
  version: 1;
  tabId: number;
  startedAtMs: number;
  events: TraceEvent[];
  truncated?: boolean;
  droppedEvents?: number;
};

export type Finding = {
  id: string;
  severity: "HIGH" | "MED" | "LOW";
  confidence?: "HIGH" | "MED" | "LOW";
  title: string;
  why?: string;
  fix: string;
  evidence?: string[];
};

export type LiveSummary = {
  tabId: number;
  hasAuthSignals: boolean;
  findings: Finding[];
  lastEventAtMs?: number;
  eventCount: number;
  traceTruncated?: boolean;
  droppedEvents?: number;
};
