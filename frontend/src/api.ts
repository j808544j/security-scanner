export type Status = "PASS" | "FAIL" | "CANNOT_SCAN";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface Scan {
  id: string;
  status: "RUNNING" | "COMPLETED" | "FAILED";
  started_at: string;
  finished_at: string | null;
  account_ids: string[];
  error: string | null;
  score: number | null;
  counts: Record<Status, number>;
  fail_counts_by_severity: Record<Severity, number>;
  accounts: Array<{ account_id: string; score: number | null; counts: Record<Status, number> }>;
}

export interface Finding {
  id: number;
  check_id: string;
  title: string;
  provider: string;
  account_id: string;
  region: string | null;
  resource_id: string | null;
  status: Status;
  severity: Severity;
  details: string;
}

export interface FindingsPage {
  items: Finding[];
  total: number;
  page: number;
  page_size: number;
}

export async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, options);
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    if (typeof body?.detail === "string") throw new Error(body.detail);
    throw new Error(`The API returned HTTP ${response.status}.`);
  }
  return response.json();
}
