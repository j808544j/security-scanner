// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { App } from "./App";
import type { Scan } from "./api";

const running: Scan = {
  id: "scan-1",
  status: "RUNNING",
  started_at: "2026-10-01T00:00:00Z",
  finished_at: null,
  error: null,
  account_ids: ["aws-account"],
  counts: { PASS: 0, FAIL: 0, CANNOT_SCAN: 0 },
  fail_counts_by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
  score: null,
  accounts: [],
};
const completed: Scan = {
  ...running,
  status: "COMPLETED",
  finished_at: "2026-10-01T00:00:03Z",
  counts: { PASS: 2, FAIL: 3, CANNOT_SCAN: 0 },
  score: 40,
};

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

test("Run scan shows RUNNING and polls until the result appears", async () => {
  vi.useFakeTimers();
  let scans: Scan[] = [];
  vi.stubGlobal("fetch", async (path: string, options?: RequestInit) => {
    if (path === "/api/scans" && options?.method === "POST") {
      scans = [running];
      return Response.json(running, { status: 202 });
    }
    return Response.json(scans);
  });
  await act(async () => { render(<App />); });
  await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Run scan" })); });
  const result = within(screen.getByRole("region", { name: "Latest scan" }));
  expect(result.getByText("RUNNING")).toBeTruthy();
  scans = [completed];
  await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
  expect(result.getByText("COMPLETED")).toBeTruthy();
  expect(result.getByText("40.0")).toBeTruthy();
  expect(result.getByText("2")).toBeTruthy();
  expect(result.getByText("3")).toBeTruthy();
});

test("findings obey filters and display snapshot strings as text", async () => {
  window.history.replaceState(null, "", "/#/scans/scan-1");
  const details = "<img src=x onerror=alert('untrusted-input')> temporary rule for vendor support";
  const finding = {
    id: 1, scan_id: "scan-1", check_id: "GCP-VPC-01",
    title: "Firewall rule doesn't expose SSH or RDP to the internet",
    provider: "gcp", account_id: "example-corp-gcp", region: "global",
    resource_id: "allow-rdp-anywhere", status: "FAIL", severity: "CRITICAL", details,
  };
  vi.stubGlobal("fetch", async (path: string) => {
    const url = new URL(path, window.location.origin);
    if (url.pathname === "/api/scans/scan-1") return Response.json(completed);
    const items = url.searchParams.get("status") === "PASS" ? [] : [finding];
    return Response.json({ items, total: items.length, page: 1, page_size: 25 });
  });
  render(<App />);
  expect(await screen.findByText(details)).toBeTruthy();
  expect(screen.queryByRole("img")).toBeNull();
  fireEvent.change(screen.getByLabelText("Status"), { target: { value: "PASS" } });
  expect(await screen.findByText("No findings match these filters.")).toBeTruthy();
});
