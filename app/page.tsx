'use client';

import React, { useEffect, useMemo, useRef, useState } from 'react';

type ToolKey =
  | 'semgrep'
  | 'codeql'
  | 'gitleaks'
  | 'syft'
  | 'osv'
  | 'kics'
  | 'trivy'
  | 'zap'
  | 'noir';

type ToolDef = {
  key: ToolKey;
  name: string;
  description: string;
  scanType: string; // DefectDojo scan type name (display only in UI for now)
  defaultEnabled: boolean;
};

type ToolRunStatus = 'idle' | 'pending' | 'running' | 'success' | 'failed';

type ToolRunResult = {
  key: ToolKey;
  status: ToolRunStatus;
  findings: number;
  startedAt?: number;
  finishedAt?: number;
  reportPath?: string;
  error?: string;
};

type Config = {
  defectDojoUrl: string;
  apiKey: string; // stored locally only for UI; no backend calls in this step
  productName: string;
  engagementName: string;
  zapTarget: string;
  enableReimport: boolean;
  tools: Record<ToolKey, boolean>;
};

const ALL_TOOLS: ToolDef[] = [
  {
    key: 'semgrep',
    name: 'Semgrep',
    description: 'Static code analysis with standard rules; excludes non-code files.',
    scanType: 'Semgrep JSON Report',
    defaultEnabled: true,
  },
  {
    key: 'codeql',
    name: 'CodeQL',
    description: 'Database creation and analysis for code vulnerabilities.',
    scanType: 'SARIF',
    defaultEnabled: true,
  },
  {
    key: 'gitleaks',
    name: 'Gitleaks',
    description: 'Secrets detection scanning full repository history.',
    scanType: 'Gitleaks Scan',
    defaultEnabled: true,
  },
  {
    key: 'syft',
    name: 'Syft',
    description: 'SBOM generation (CycloneDX) for repository or container image.',
    scanType: 'CycloneDX JSON',
    defaultEnabled: true,
  },
  {
    key: 'osv',
    name: 'osv-scanner',
    description: 'Dependency vulnerability scan using the generated SBOM.',
    scanType: 'OSV Scanner',
    defaultEnabled: true,
  },
  {
    key: 'kics',
    name: 'KICS',
    description: 'IaC misconfiguration detection across Terraform, YAML, etc.',
    scanType: 'KICS Scan',
    defaultEnabled: true,
  },
  {
    key: 'trivy',
    name: 'Trivy',
    description: 'Vulnerabilities, secrets, and IaC multi-scan.',
    scanType: 'Trivy Scan',
    defaultEnabled: true,
  },
  {
    key: 'zap',
    name: 'OWASP ZAP',
    description: 'Automated DAST (Baseline Scan) against the deployed endpoint.',
    scanType: 'ZAP Scan',
    defaultEnabled: false,
  },
  {
    key: 'noir',
    name: 'Noir',
    description: 'Application analysis with generic findings conversion.',
    scanType: 'Generic Findings Import',
    defaultEnabled: false,
  },
];

const DEFAULT_CONFIG: Config = {
  defectDojoUrl: '',
  apiKey: '',
  productName: '',
  engagementName: '',
  zapTarget: '',
  enableReimport: true,
  tools: ALL_TOOLS.reduce((acc, t) => {
    acc[t.key] = t.defaultEnabled;
    return acc;
  }, {} as Record<ToolKey, boolean>),
};

const STORAGE_KEYS = {
  config: 'securityScannerConfig',
  theme: 'theme',
} as const;

function classNames(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(' ');
}

function formatDate(ts?: number) {
  if (!ts) return '-';
  const d = new Date(ts);
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
}

function StatusPill({ status }: { status: ToolRunStatus }) {
  const map: Record<
    ToolRunStatus,
    { label: string; bg: string; dot: string; text: string }
  > = {
    idle: { label: 'Idle', bg: 'bg-slate-200 dark:bg-slate-800', dot: 'bg-slate-500', text: 'text-slate-800 dark:text-slate-100' },
    pending: { label: 'Pending', bg: 'bg-slate-200 dark:bg-slate-800', dot: 'bg-slate-400', text: 'text-slate-800 dark:text-slate-100' },
    running: { label: 'Running', bg: 'bg-blue-100 dark:bg-blue-900/40', dot: 'bg-blue-500', text: 'text-blue-800 dark:text-blue-100' },
    success: { label: 'Success', bg: 'bg-emerald-100 dark:bg-emerald-900/40', dot: 'bg-emerald-500', text: 'text-emerald-800 dark:text-emerald-100' },
    failed: { label: 'Failed', bg: 'bg-rose-100 dark:bg-rose-900/40', dot: 'bg-rose-500', text: 'text-rose-800 dark:text-rose-100' },
  };

  const s = map[status];
  return (
    <span
      className={classNames(
        'inline-flex items-center gap-2 rounded-full px-2.5 py-1 text-xs font-medium',
        s.bg,
        s.text
      )}
    >
      <span className={classNames('h-1.5 w-1.5 rounded-full', s.dot)} />
      {s.label}
    </span>
  );
}

export default function Home() {
  const [config, setConfig] = useState<Config>(DEFAULT_CONFIG);
  const [results, setResults] = useState<Record<ToolKey, ToolRunResult>>(
    () =>
      ALL_TOOLS.reduce((acc, t) => {
        acc[t.key] = { key: t.key, status: 'idle', findings: 0 };
        return acc;
      }, {} as Record<ToolKey, ToolRunResult>)
  );
  const [isSaving, setIsSaving] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [lastRunAt, setLastRunAt] = useState<number | undefined>(undefined);
  const timeoutsRef = useRef<NodeJS.Timeout[]>([]);
  const [mounted, setMounted] = useState(false);

  // Theme
  useEffect(() => {
    setMounted(true);
    const savedTheme = typeof window !== 'undefined' ? localStorage.getItem(STORAGE_KEYS.theme) : null;
    const prefersDark = typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    const shouldDark = savedTheme ? savedTheme === 'dark' : prefersDark;
    if (shouldDark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, []);

  const isDark = useMemo(() => {
    if (!mounted) return false;
    return document.documentElement.classList.contains('dark');
  }, [mounted]);

  function toggleTheme() {
    const next = !isDark;
    if (next) document.documentElement.classList.add('dark');
    else document.documentElement.classList.remove('dark');
    localStorage.setItem(STORAGE_KEYS.theme, next ? 'dark' : 'light');
  }

  // Load saved config
  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEYS.config);
      if (raw) {
        const parsed = JSON.parse(raw) as Partial<Config>;
        setConfig((prev) => ({
          ...prev,
          ...parsed,
          tools: { ...prev.tools, ...(parsed.tools ?? {}) },
        }));
      }
    } catch {
      // ignore
    }
  }, []);

  function updateToolEnabled(key: ToolKey, enabled: boolean) {
    setConfig((c) => ({ ...c, tools: { ...c.tools, [key]: enabled } }));
  }

  function saveConfig() {
    setIsSaving(true);
    try {
      localStorage.setItem(STORAGE_KEYS.config, JSON.stringify(config));
    } finally {
      setTimeout(() => setIsSaving(false), 500);
    }
  }

  // Simulated run logic: no backend, for UI only
  function simulateRun() {
    // reset and mark pending
    const enabledTools = ALL_TOOLS.filter((t) => config.tools[t.key]);
    if (enabledTools.length === 0) {
      // show quick feedback by flipping all to idle; no toast system, keep minimal
      return;
    }

    // Clear any pending timers
    timeoutsRef.current.forEach(clearTimeout);
    timeoutsRef.current = [];

    const started = Date.now();
    setLastRunAt(started);

    setResults((prev) => {
      const updated = { ...prev };
      for (const tool of ALL_TOOLS) {
        if (config.tools[tool.key]) {
          updated[tool.key] = {
            key: tool.key,
            status: 'pending',
            findings: 0,
          };
        } else {
          updated[tool.key] = {
            key: tool.key,
            status: 'idle',
            findings: 0,
          };
        }
      }
      return updated;
    });

    setIsSimulating(true);

    // stagger simulated execution
    enabledTools.forEach((tool, idx) => {
      // move to running
      const t1 = setTimeout(() => {
        setResults((prev) => ({
          ...prev,
          [tool.key]: {
            ...prev[tool.key],
            status: 'running',
            startedAt: Date.now(),
          },
        }));
      }, 300 + idx * 150);
      timeoutsRef.current.push(t1);

      // finish with success/failure and findings
      const duration = 1200 + Math.round(Math.random() * 1800) + idx * 250;
      const t2 = setTimeout(() => {
        const isFailure = Math.random() < 0.08; // small chance of fail in demo
        const findings = isFailure ? 0 : Math.floor(Math.random() * 12);
        setResults((prev) => ({
          ...prev,
          [tool.key]: {
            ...prev[tool.key],
            status: isFailure ? 'failed' : 'success',
            findings,
            finishedAt: Date.now(),
            reportPath: isFailure ? undefined : `${tool.key}_report.json`,
            error: isFailure ? 'Simulated network error' : undefined,
          },
        }));

        // if last tool finishes, stop simulating flag
        if (tool.key === enabledTools[enabledTools.length - 1].key) {
          setTimeout(() => setIsSimulating(false), 400);
        }
      }, duration);
      timeoutsRef.current.push(t2);
    });
  }

  useEffect(() => {
    return () => {
      timeoutsRef.current.forEach(clearTimeout);
    };
  }, []);

  const totals = useMemo(() => {
    const enabledCount = Object.values(config.tools).filter(Boolean).length;
    const successFindings = Object.values(results).reduce((acc, r) => acc + (r.status === 'success' ? r.findings : 0), 0);
    const statuses = Object.values(results).filter((r) => config.tools[r.key]).map((r) => r.status);
    const allDone = statuses.length > 0 && statuses.every((s) => s === 'success' || s === 'failed');
    const anyRunning = statuses.some((s) => s === 'running' || s === 'pending');
    const failed = statuses.filter((s) => s === 'failed').length;
    return { enabledCount, successFindings, allDone, anyRunning, failed };
  }, [config.tools, results]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-white dark:from-slate-950 dark:to-slate-900 text-slate-900 dark:text-slate-100">
      <div className="mx-auto max-w-7xl px-6 py-8">
        <header className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Security Scanning Dashboard</h1>
            <p className="mt-1 text-slate-600 dark:text-slate-300">
              Configure tools, simulate runs, and review results before integrating CI/CD and DefectDojo.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={toggleTheme}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-300 dark:border-slate-700 px-3 py-2 text-sm hover:bg-slate-100 dark:hover:bg-slate-800"
              aria-label="Toggle theme"
              type="button"
            >
              <span className="h-4 w-4 rounded-full bg-gradient-to-br from-yellow-300 to-orange-500 dark:from-indigo-400 dark:to-purple-500" />
              {isDark ? 'Dark' : 'Light'}
            </button>
            <button
              onClick={saveConfig}
              disabled={isSaving}
              className={classNames(
                'inline-flex items-center gap-2 rounded-lg bg-slate-900 text-white dark:bg-white dark:text-slate-900 px-4 py-2 text-sm font-medium shadow-sm',
                isSaving && 'opacity-70'
              )}
              type="button"
            >
              {isSaving ? 'Saving…' : 'Save Configuration'}
            </button>
            <button
              onClick={simulateRun}
              disabled={isSimulating || Object.values(config.tools).every((v) => !v)}
              className={classNames(
                'inline-flex items-center gap-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 text-sm font-semibold shadow-sm',
                (isSimulating || Object.values(config.tools).every((v) => !v)) && 'opacity-60 cursor-not-allowed'
              )}
              type="button"
            >
              {isSimulating ? 'Running…' : 'Simulate Run'}
            </button>
          </div>
        </header>

        {/* Summary cards */}
        <section className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <SummaryCard
            title="Tools Enabled"
            value={`${totals.enabledCount} / ${ALL_TOOLS.length}`}
            subtitle="Configure which scanners to include"
          />
          <SummaryCard
            title="Total Findings (Simulated)"
            value={`${totals.successFindings}`}
            subtitle="From successful tool runs only"
          />
          <SummaryCard
            title="Run Status"
            value={totals.anyRunning ? 'In Progress' : totals.allDone ? 'Complete' : 'Idle'}
            badge={totals.anyRunning ? 'running' : totals.allDone ? 'success' : 'idle'}
            subtitle={lastRunAt ? `Last run: ${formatDate(lastRunAt)}` : 'No runs yet'}
          />
          <SummaryCard
            title="Upload Mode"
            value={config.enableReimport ? 'Reimport (dedupe)' : 'Import'}
            subtitle="DefectDojo deduplication preference"
          />
        </section>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Configuration column */}
          <section className="lg:col-span-1 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
            <h2 className="text-lg font-semibold mb-4">Configuration</h2>
            <div className="space-y-6">
              <div>
                <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">DefectDojo</h3>
                <div className="mt-3 space-y-3">
                  <LabeledInput
                    label="DefectDojo URL"
                    placeholder="https://defectdojo.example.com"
                    value={config.defectDojoUrl}
                    onChange={(v) => setConfig((c) => ({ ...c, defectDojoUrl: v }))}
                  />
                  <LabeledInput
                    label="Product Name"
                    placeholder="My Product"
                    value={config.productName}
                    onChange={(v) => setConfig((c) => ({ ...c, productName: v }))}
                  />
                  <LabeledInput
                    label="Engagement Name"
                    placeholder="CI/CD Security Scan"
                    value={config.engagementName}
                    onChange={(v) => setConfig((c) => ({ ...c, engagementName: v }))}
                  />
                  <LabeledInput
                    label="API Key"
                    type="password"
                    placeholder="••••••••••"
                    value={config.apiKey}
                    onChange={(v) => setConfig((c) => ({ ...c, apiKey: v }))}
                  />
                  <ToggleRow
                    label="Use Reimport (deduplication)"
                    description="Enable DefectDojo reimport to ensure continuous deduplication across runs."
                    enabled={config.enableReimport}
                    onToggle={(v) => setConfig((c) => ({ ...c, enableReimport: v }))}
                  />
                </div>
              </div>

              <div className="pt-2">
                <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">OWASP ZAP</h3>
                <div className="mt-3 space-y-3">
                  <LabeledInput
                    label="Target Application Endpoint"
                    placeholder="https://app.example.com"
                    value={config.zapTarget}
                    onChange={(v) => setConfig((c) => ({ ...c, zapTarget: v }))}
                  />
                </div>
              </div>

              <div className="pt-2">
                <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">Tools</h3>
                <div className="mt-3 divide-y divide-slate-200 dark:divide-slate-800 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                  {ALL_TOOLS.map((tool) => {
                    const enabled = config.tools[tool.key];
                    return (
                      <div key={tool.key} className="flex items-start justify-between gap-4 p-4 bg-white dark:bg-slate-900">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{tool.name}</span>
                            <span className="text-xs text-slate-500 dark:text-slate-400">({tool.scanType})</span>
                          </div>
                          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">{tool.description}</p>
                        </div>
                        <Switch enabled={enabled} onChange={(v) => updateToolEnabled(tool.key, v)} />
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="pt-2">
                <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">Pre-flight Checklist</h3>
                <ul className="mt-3 space-y-2 text-sm text-slate-600 dark:text-slate-400 list-disc pl-5">
                  <li>Ensure all CLI tools are installed on the runner.</li>
                  <li>Verify DefectDojo URL and API key are valid.</li>
                  <li>Confirm Product and Engagement exist in DefectDojo.</li>
                  <li>Provide a reachable endpoint for ZAP DAST scans.</li>
                </ul>
              </div>
            </div>
          </section>

          {/* Results column */}
          <section className="lg:col-span-2 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">Run Results</h2>
              {totals.anyRunning && (
                <div className="flex items-center gap-3">
                  <div className="h-2 w-2 animate-pulse rounded-full bg-blue-500" />
                  <span className="text-sm text-slate-600 dark:text-slate-300">Simulating run…</span>
                </div>
              )}
            </div>

            <div className="mt-4 overflow-hidden rounded-xl border border-slate-200 dark:border-slate-800">
              <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-800">
                <thead className="bg-slate-50 dark:bg-slate-950/40">
                  <tr>
                    <Th>Tool</Th>
                    <Th>Scan Type</Th>
                    <Th className="text-center">Enabled</Th>
                    <Th>Status</Th>
                    <Th className="text-center">Findings</Th>
                    <Th>Report</Th>
                    <Th>Started</Th>
                    <Th>Finished</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800 bg-white dark:bg-slate-900">
                  {ALL_TOOLS.map((tool) => {
                    const res = results[tool.key];
                    const enabled = config.tools[tool.key];
                    return (
                      <tr key={tool.key} className={classNames(!enabled && 'opacity-60')}>
                        <Td>
                          <div className="font-medium">{tool.name}</div>
                          <div className="text-xs text-slate-500 dark:text-slate-400">{tool.description}</div>
                        </Td>
                        <Td>
                          <span className="text-sm text-slate-700 dark:text-slate-300">{tool.scanType}</span>
                        </Td>
                        <Td className="text-center">
                          <span
                            className={classNames(
                              'inline-flex items-center justify-center rounded-md px-2 py-0.5 text-xs font-medium',
                              enabled
                                ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-100'
                                : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200'
                            )}
                          >
                            {enabled ? 'On' : 'Off'}
                          </span>
                        </Td>
                        <Td>
                          <StatusPill status={res?.status ?? 'idle'} />
                        </Td>
                        <Td className="text-center">
                          {res?.status === 'success' ? res.findings : res?.status === 'failed' ? '—' : '…'}
                        </Td>
                        <Td>
                          {res?.reportPath ? (
                            <span className="text-blue-600 dark:text-blue-400 text-sm underline underline-offset-2 cursor-default">
                              {res.reportPath}
                            </span>
                          ) : (
                            <span className="text-slate-400 text-sm">—</span>
                          )}
                        </Td>
                        <Td>{formatDate(res?.startedAt)}</Td>
                        <Td>{formatDate(res?.finishedAt)}</Td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Footer status */}
            <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
              <div className="text-sm text-slate-600 dark:text-slate-300">
                {totals.anyRunning
                  ? 'Run in progress…'
                  : totals.allDone
                  ? totals.failed > 0
                    ? `Run completed with ${totals.failed} failure(s).`
                    : 'Run completed successfully.'
                  : 'Awaiting run.'}
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400">
                Placeholder UI only. Backend execution and DefectDojo uploads are implemented in subsequent steps.
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function SummaryCard({
  title,
  value,
  subtitle,
  badge,
}: {
  title: string;
  value: string;
  subtitle?: string;
  badge?: ToolRunStatus;
}) {
  return (
    <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-600 dark:text-slate-300">{title}</div>
        {badge ? <StatusPill status={badge} /> : null}
      </div>
      <div className="mt-2 text-2xl font-semibold tracking-tight">{value}</div>
      {subtitle ? <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">{subtitle}</div> : null}
    </div>
  );
}

function LabeledInput({
  label,
  placeholder,
  value,
  onChange,
  type = 'text',
}: {
  label: string;
  placeholder?: string;
  value: string;
  onChange: (v: string) => void;
  type?: 'text' | 'password' | 'url';
}) {
  const id = React.useId();
  return (
    <div>
      <label htmlFor={id} className="block text-xs font-medium text-slate-700 dark:text-slate-300">
        {label}
      </label>
      <input
        id={id}
        type={type}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="mt-1 w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm outline-none ring-0 focus:border-blue-500 dark:focus:border-blue-400"
      />
    </div>
  );
}

function Switch({
  enabled,
  onChange,
}: {
  enabled: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={enabled}
      onClick={() => onChange(!enabled)}
      className={classNames(
        'relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none',
        enabled ? 'bg-blue-600' : 'bg-slate-300 dark:bg-slate-700'
      )}
    >
      <span
        className={classNames(
          'inline-block h-5 w-5 transform rounded-full bg-white dark:bg-slate-200 transition-transform',
          enabled ? 'translate-x-5' : 'translate-x-1'
        )}
      />
    </button>
  );
}

function ToggleRow({
  label,
  description,
  enabled,
  onToggle,
}: {
  label: string;
  description?: string;
  enabled: boolean;
  onToggle: (v: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div>
        <div className="font-medium text-sm">{label}</div>
        {description ? <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">{description}</p> : null}
      </div>
      <Switch enabled={enabled} onChange={onToggle} />
    </div>
  );
}

function Th({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <th
      scope="col"
      className={classNames(
        'px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-300',
        className
      )}
    >
      {children}
    </th>
  );
}

function Td({ children, className }: { children: React.ReactNode; className?: string }) {
  return <td className={classNames('px-4 py-3 align-top text-sm', className)}>{children}</td>;
}
