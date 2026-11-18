import { useEffect, useState } from "react";
import { request } from "./api";
import type { FindingsPage, Scan } from "./api";

const STATUSES = ["PASS", "FAIL", "CANNOT_SCAN"] as const;
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
const dateFormatter = new Intl.DateTimeFormat(undefined, {
  year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit",
  second: "2-digit", timeZoneName: "short",
});
const score = (value: number | null) => value === null ? "N/A" : value.toFixed(1);
const scanLink = (id: string) => `#/scans/${encodeURIComponent(id)}`;
const isRunning = (scan: Scan) => scan.status === "RUNNING";

function useScanData<T>(path: string, shouldPoll?: (value: T) => boolean) {
  const [response, setResponse] = useState<{ path: string; data?: T; error?: string }>();
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let timer: number;
    async function load() {
      try {
        const result = await request<T>(path, { signal: controller.signal });
        if (controller.signal.aborted) return;
        setResponse({ path, data: result });
        if (shouldPoll?.(result)) timer = window.setTimeout(load, 1000);
      } catch (error) {
        if (!controller.signal.aborted) {
          const message = error instanceof Error ? error.message : "Request failed.";
          setResponse((previous) => ({
            path,
            data: previous?.path === path ? previous.data : undefined,
            error: message,
          }));
        }
      }
    }
    void load();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [path, revision, shouldPoll]);

  const current = response?.path === path ? response : undefined;
  return {
    data: current?.data,
    error: current?.error,
    update: (transform: (previous: T | undefined) => T) => {
      setResponse((previous) => ({
        path,
        data: transform(previous?.path === path ? previous.data : undefined),
      }));
    },
    reload: () => setRevision((value) => value + 1),
  };
}

function Badge({ value }: { value: string }) {
  return <span className={`badge badge-${value.toLowerCase()}`}>{value}</span>;
}

function Metrics({ scan }: { scan: Scan }) {
  return <dl className="metrics">
    <div><dt>Posture score</dt><dd>{score(scan.score)}</dd></div>
    {STATUSES.map((status) => <div key={status}>
      <dt><Badge value={status} /></dt><dd>{scan.counts[status]}</dd>
    </div>)}
  </dl>;
}

function ErrorNotice({ message, retry }: { message: string; retry?: () => void }) {
  return <div className="notice error" role="alert">
    {message}
    {retry && <button className="secondary" onClick={retry}>Retry</button>}
  </div>;
}

const hasRunning = (scans: Scan[]) => scans.some(isRunning);

function ScanList() {
  const scans = useScanData<Scan[]>("/api/scans", hasRunning);
  const [submitting, setSubmitting] = useState(false);
  const [startError, setStartError] = useState("");
  const latest = scans.data?.[0];

  async function startScan() {
    setSubmitting(true);
    setStartError("");
    try {
      const scan = await request<Scan>("/api/scans", { method: "POST" });
      scans.update((current) => [scan, ...(current ?? []).filter((item) => item.id !== scan.id)]);
      scans.reload();
    } catch (error) {
      setStartError(error instanceof Error ? error.message : "Scan could not be started.");
    } finally {
      setSubmitting(false);
    }
  }

  return <>
    <header className="page-heading">
      <div><h1>Scans</h1><p>Evaluate cloud configuration from the inventory snapshot.</p></div>
      <button onClick={startScan} disabled={submitting || !scans.data}>
        {submitting ? "Starting…" : "Run scan"}
      </button>
    </header>
    {startError && <ErrorNotice message={startError} />}
    {scans.error && <ErrorNotice message={scans.error} retry={scans.reload} />}
    {!scans.data && !scans.error && <p className="notice" role="status">Loading scans…</p>}
    {latest && <section className="panel" aria-label="Latest scan" aria-live="polite">
      <header className="panel-heading">
        <div><h2>Latest scan</h2><Badge value={latest.status} /></div>
        <a href={scanLink(latest.id)}>View findings <span aria-hidden="true">→</span></a>
      </header>
      {latest.error && <ErrorNotice message={latest.error} />}
      {latest.status === "COMPLETED" && <Metrics scan={latest} />}
      {latest.status === "RUNNING" && <p className="muted">Evaluating {latest.account_ids.length} accounts…</p>}
    </section>}
    {scans.data && <section className="panel">
      <header className="panel-heading"><h2>Scan history</h2></header>
      {scans.data.length === 0 ? <p className="notice">No scans yet. Run a scan to see your findings.</p> :
        <div className="table-wrap"><table>
          <thead><tr><th>Scan ID</th><th>Status</th><th>Started</th><th>Duration</th><th>Score</th></tr></thead>
          <tbody>{scans.data.map((scan) => <tr key={scan.id}>
            <td><a className="identifier" href={scanLink(scan.id)}>{scan.id}</a></td>
            <td><Badge value={scan.status} /></td>
            <td>{dateFormatter.format(new Date(scan.started_at))}</td>
            <td>{scan.finished_at
              ? `${((Date.parse(scan.finished_at) - Date.parse(scan.started_at)) / 1000).toFixed(1)} s`
              : "—"}</td>
            <td>{score(scan.score)}</td>
          </tr>)}</tbody>
        </table></div>}
    </section>}
  </>;
}

function Findings({ scan }: { scan: Scan }) {
  const options = {
    status: STATUSES,
    severity: SEVERITIES,
    provider: ["aws", "azure", "gcp"],
    account_id: scan.account_ids,
  };
  const labels = { status: "Status", severity: "Severity", provider: "Provider", account_id: "Account" };
  type Filter = keyof typeof options;
  const [query, setQuery] = useState({ page: 1, filters: { status: "", severity: "", provider: "", account_id: "" } });
  const parameters = new URLSearchParams({ page: String(query.page) });
  for (const [key, value] of Object.entries(query.filters)) {
    if (value) parameters.set(key, value);
  }
  const data = useScanData<FindingsPage>(`/api/scans/${encodeURIComponent(scan.id)}/findings?${parameters}`);
  const result = data.data;
  return <section className="panel">
    <header className="panel-heading"><h2>Findings</h2></header>
    <div className="filters">{(Object.keys(options) as Filter[]).map((key) => <label key={key}>
      {labels[key]}
      <select value={query.filters[key]} onChange={(event) => {
        setQuery({ page: 1, filters: { ...query.filters, [key]: event.target.value } });
      }}>
        <option value="">All</option>
        {options[key].map((value) => <option key={value}>{value}</option>)}
      </select>
    </label>)}</div>
    {data.error && <ErrorNotice message={data.error} retry={data.reload} />}
    {!result && !data.error && <p className="notice" role="status">Loading findings…</p>}
    {result && (result.total === 0 ? <p className="notice">No findings match these filters.</p> : <>
      <div className="table-wrap"><table>
        <thead><tr><th>Status</th><th>Severity</th><th>Check</th><th>Resource</th>
          <th>Account</th><th>Details</th></tr></thead>
        <tbody>{result.items.map((finding) => <tr key={finding.id}>
          <td><Badge value={finding.status} /></td>
          <td><Badge value={finding.severity} /></td>
          <td>{finding.title}<small>{finding.check_id}</small></td>
          <td>{finding.resource_id ?? "—"}<small>{finding.region ?? "—"}</small></td>
          <td>{finding.account_id}<small>{finding.provider}</small></td>
          <td>{finding.details}</td>
        </tr>)}</tbody>
      </table></div>
      <nav className="pagination" aria-label="Findings pages">
        <button className="secondary" disabled={query.page <= 1}
          onClick={() => setQuery({ ...query, page: query.page - 1 })}>Previous</button>
        <span>Page {result.page} of {Math.ceil(result.total / result.page_size)} · {result.total} findings</span>
        <button className="secondary" disabled={query.page * result.page_size >= result.total}
          onClick={() => setQuery({ ...query, page: query.page + 1 })}>Next</button>
      </nav>
    </>)}
  </section>;
}

function ScanDetail({ id }: { id: string }) {
  const { data: scan, error, reload } = useScanData<Scan>(`/api/scans/${encodeURIComponent(id)}`, isRunning);
  return <>
    <header className="page-heading">
      <div><a href="#/scans">← All scans</a><h1>Scan details</h1><p className="identifier">{id}</p></div>
      {scan && <Badge value={scan.status} />}
    </header>
    {error && <ErrorNotice message={error} retry={reload} />}
    {!scan && !error && <p className="notice" role="status">Loading scan…</p>}
    {scan?.error && <ErrorNotice message={scan.error} />}
    {scan && isRunning(scan) && <p className="notice" role="status">Evaluating {scan.account_ids.length} accounts…</p>}
    {scan?.status === "COMPLETED" && <>
      <section className="panel"><header className="panel-heading"><h2>Scan results</h2></header>
        <Metrics scan={scan} />
        <dl className="severity-totals" aria-label="Failures by severity">
          {SEVERITIES.map((severity) => <div key={severity}>
            <dt><Badge value={severity} /></dt><dd>{scan.fail_counts_by_severity[severity]} failed</dd>
          </div>)}
        </dl>
      </section>
      <section className="panel"><header className="panel-heading"><h2>Account scores</h2></header>
        <div className="table-wrap"><table>
          <thead><tr><th>Account</th><th>PASS</th><th>FAIL</th><th>CANNOT_SCAN</th><th>Score</th></tr></thead>
          <tbody>{scan.accounts.map((account) => <tr key={account.account_id}>
            <td className="identifier">{account.account_id}</td>
            {STATUSES.map((status) => <td key={status}>{account.counts[status]}</td>)}
            <td>{score(account.score)}</td>
          </tr>)}</tbody>
        </table></div>
      </section>
      <Findings scan={scan} />
    </>}
  </>;
}

export function App() {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    function navigate() { setHash(window.location.hash); }
    window.addEventListener("hashchange", navigate);
    return () => window.removeEventListener("hashchange", navigate);
  }, []);
  const scanId = hash.match(/^#\/scans\/([\w-]+)$/)?.[1];
  return <>
    <header className="masthead">
      <div className="masthead-inner"><a href="#/scans" className="brand">Mini Gauntlet</a></div>
    </header>
    <main>{scanId ? <ScanDetail key={scanId} id={scanId} /> : <ScanList />}</main>
  </>;
}
