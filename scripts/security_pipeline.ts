/* eslint-disable no-console */

import { spawn } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { mkdir, readFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'

type ToolKey =
  | 'semgrep'
  | 'codeql'
  | 'gitleaks'
  | 'syft'
  | 'osv'
  | 'kics'
  | 'trivy'
  | 'zap'
  | 'noir'

type Options = {
  outDir: string
  ddUrl?: string
  apiKey?: string
  productName?: string
  engagementName?: string
  engagementId?: number
  zapTarget?: string
  strict: boolean
  enable: Partial<Record<ToolKey, boolean>>
  minSeverity: 'Info' | 'Low' | 'Medium' | 'High' | 'Critical'
  closeOld: boolean
  active: boolean
  verified: boolean
  titleSuffix?: string
  branchTag?: string
  commitHash?: string
  buildId?: string
}

type UploadSummaryEntry = {
  key: ToolKey
  ok: boolean
  file?: string
  status?: number
  error?: string
}

type ReportFindingStat = {
  key: ToolKey
  report: string
  found: number
}

type PipelineSummary = {
  run: {
    startedAt: string
    finishedAt: string
    outDir: string
    zapTarget?: string
  }
  reports: ReportFindingStat[]
  uploads: UploadSummaryEntry[]
  validation?: {
    engagementId?: number
    testsCount?: number
    tests?: Array<{ id: number; title?: string; typeName?: string; targetStart?: string }>
    findingsActive?: number
    findingsDuplicate?: number
    info?: string
  }
  warnings: string[]
}

const FILES: Record<ToolKey, string> = {
  semgrep: 'semgrep_report.json',
  codeql: 'codeql_report.sarif',
  gitleaks: 'gitleaks_report.json',
  syft: 'sbom.cdx.json',
  osv: 'osv_report.json',
  kics: 'kics_report.json',
  trivy: 'trivy_report.json',
  zap: 'zap_report.json',
  noir: 'noir_generic.json',
}

const TOOL_TITLES: Record<ToolKey, string> = {
  semgrep: 'Semgrep',
  codeql: 'CodeQL',
  gitleaks: 'Gitleaks',
  syft: 'Syft SBOM',
  osv: 'OSV Scanner (from SBOM)',
  kics: 'KICS',
  trivy: 'Trivy',
  zap: 'OWASP ZAP Baseline',
  noir: 'Noir (Generic Findings)',
}

function readFlag(name: string): string | undefined {
  const idx = process.argv.indexOf(`--${name}`)
  if (idx >= 0 && idx < process.argv.length - 1) {
    return process.argv[idx + 1]
  }
  return undefined
}
function hasFlag(name: string): boolean {
  return process.argv.includes(`--${name}`)
}
function toBool(val: string | undefined, fallback: boolean) {
  if (typeof val !== 'string') return fallback
  const v = val.toLowerCase()
  if (['1', 'true', 'yes', 'y'].includes(v)) return true
  if (['0', 'false', 'no', 'n'].includes(v)) return false
  return fallback
}

function parseOptions(): Options {
  const outDir = resolve(readFlag('out-dir') || process.env.SECURITY_SCAN_OUT_DIR || 'security-reports')
  const ddUrl = readFlag('dd-url') || process.env.DD_URL || process.env.DEFECTDOJO_URL
  const apiKey = readFlag('api-key') || process.env.DD_API_KEY || process.env.DEFECTDOJO_API_KEY
  const productName = readFlag('product-name') || process.env.DD_PRODUCT_NAME
  const engagementName = readFlag('engagement-name') || process.env.DD_ENGAGEMENT_NAME
  const engagementIdRaw = readFlag('engagement-id') || process.env.DD_ENGAGEMENT_ID
  const zapTarget = readFlag('zap-target') || process.env.ZAP_TARGET || process.env.ZAP_BASELINE_TARGET
  const strict = hasFlag('strict') || toBool(process.env.DD_STRICT, false)
  const minSeverity = (readFlag('min-severity') || process.env.DD_MIN_SEVERITY || 'Info') as Options['minSeverity']
  const closeOld = toBool(readFlag('close-old') || process.env.DD_CLOSE_OLD, false)
  const active = toBool(readFlag('active') || process.env.DD_ACTIVE, true)
  const verified = toBool(readFlag('verified') || process.env.DD_VERIFIED, true)
  const titleSuffix = readFlag('title-suffix') || process.env.DD_TEST_TITLE_SUFFIX
  const branchTag = readFlag('branch') || process.env.CI_BRANCH || process.env.GIT_BRANCH
  const commitHash = readFlag('commit') || process.env.CI_COMMIT_SHA || process.env.GIT_COMMIT || process.env.COMMIT_SHA
  const buildId = readFlag('build-id') || process.env.CI_BUILD_ID || process.env.BUILD_ID || process.env.GITHUB_RUN_ID

  const enable: Partial<Record<ToolKey, boolean>> = {}
  ;(['semgrep', 'codeql', 'gitleaks', 'syft', 'osv', 'kics', 'trivy', 'zap', 'noir'] as ToolKey[]).forEach((t) => {
    const env = process.env[`ENABLE_${t.toUpperCase()}`]
    const flagEn = hasFlag(`enable-${t}`)
    const flagDis = hasFlag(`disable-${t}`)
    if (flagDis) enable[t] = false
    else if (flagEn) enable[t] = true
    else if (env) enable[t] = toBool(env, true)
  })

  return {
    outDir,
    ddUrl,
    apiKey,
    productName,
    engagementName,
    engagementId: engagementIdRaw ? Number(engagementIdRaw) : undefined,
    zapTarget,
    strict,
    enable,
    minSeverity,
    closeOld,
    active,
    verified,
    titleSuffix,
    branchTag,
    commitHash,
    buildId,
  }
}

function tsxBin(): string {
  const base = resolve(process.cwd(), 'node_modules', '.bin')
  const file = process.platform === 'win32' ? 'tsx.cmd' : 'tsx'
  const p = join(base, file)
  return existsSync(p) ? p : 'tsx'
}

async function ensureDir(path: string) {
  if (!existsSync(path)) await mkdir(path, { recursive: true })
}

function runCmd(cmd: string, args: string[], cwd: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolvePromise) => {
    const child = spawn(cmd, args, { cwd, env: process.env })
    const out: Buffer[] = []
    const err: Buffer[] = []
    child.stdout.on('data', (d) => out.push(Buffer.from(d)))
    child.stderr.on('data', (d) => err.push(Buffer.from(d)))
    child.on('close', (code) => {
      resolvePromise({
        code: code ?? 1,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      })
    })
    child.on('error', (e) => {
      resolvePromise({ code: 127, stdout: '', stderr: String(e) })
    })
  })
}

function scanArgs(opts: Options): string[] {
  const args = ['scripts/security_scan.ts', '--out-dir', opts.outDir]
  if (opts.zapTarget) args.push('--zap-target', opts.zapTarget)
  ;(Object.keys(opts.enable) as ToolKey[]).forEach((k) => {
    const v = opts.enable[k]
    if (typeof v === 'boolean') args.push(v ? `--enable-${k}` : `--disable-${k}`)
  })
  return args
}

function uploadArgs(opts: Options): string[] {
  const args = [
    'scripts/upload_to_defectdojo.ts',
    '--out-dir',
    opts.outDir,
    '--min-severity',
    opts.minSeverity,
    ...(opts.closeOld ? ['--close-old'] : []),
    ...(opts.active ? ['--active'] : []),
    ...(opts.verified ? ['--verified'] : []),
  ]
  if (opts.ddUrl) args.push('--dd-url', opts.ddUrl)
  if (opts.apiKey) args.push('--api-key', opts.apiKey)
  if (opts.productName) args.push('--product-name', opts.productName)
  if (opts.engagementName) args.push('--engagement-name', opts.engagementName)
  if (typeof opts.engagementId === 'number') args.push('--engagement-id', String(opts.engagementId))
  if (opts.titleSuffix) args.push('--title-suffix', opts.titleSuffix)
  if (opts.branchTag) args.push('--branch', opts.branchTag)
  if (opts.commitHash) args.push('--commit', opts.commitHash)
  if (opts.buildId) args.push('--build-id', opts.buildId)
  // Do not pass --strict by default; pipeline handles strictness globally
  return args
}

function countFindingsForReport(key: ToolKey, filePath: string): number {
  try {
    const raw = readFileSync(filePath, 'utf8')
    const parsed = JSON.parse(raw)

    switch (key) {
      case 'semgrep': {
        // semgrep JSON: { results: [...] }
        const results = Array.isArray((parsed as any).results) ? (parsed as any).results : []
        return results.length
      }
      case 'codeql': {
        // SARIF: { runs: [ { results: [...] } ] }
        const runs = Array.isArray((parsed as any).runs) ? (parsed as any).runs : []
        let total = 0
        for (const r of runs) {
          const res = Array.isArray((r as any).results) ? (r as any).results.length : 0
          total += res
        }
        return total
      }
      case 'gitleaks': {
        // gitleaks: array of leaks
        return Array.isArray(parsed) ? (parsed as any[]).length : 0
      }
      case 'syft': {
        // SBOM only; no findings
        return 0
      }
      case 'osv': {
        // osv-scanner: { results: [ { packages, vulnerabilities } ] }
        const results = Array.isArray((parsed as any).results) ? (parsed as any).results : []
        let total = 0
        for (const r of results) {
          const vulns = Array.isArray((r as any).vulnerabilities) ? (r as any).vulnerabilities.length : 0
          total += vulns
        }
        return total
      }
      case 'kics': {
        // kics: { queries: [ { results: [...] } ] } OR { results: [ ... ] }
        const queries = Array.isArray((parsed as any).queries) ? (parsed as any).queries : []
        if (queries.length > 0) {
          return queries.reduce((acc, q) => acc + (Array.isArray((q as any).results) ? (q as any).results.length : 0), 0)
        }
        const results = Array.isArray((parsed as any).results) ? (parsed as any).results : []
        return results.length
      }
      case 'trivy': {
        // trivy: { Results: [ { Vulnerabilities: [], Misconfigurations: [], Secrets: [] } ] }
        const results = Array.isArray((parsed as any).Results) ? (parsed as any).Results : []
        let total = 0
        for (const r of results) {
          const v = Array.isArray((r as any).Vulnerabilities) ? (r as any).Vulnerabilities.length : 0
          const m = Array.isArray((r as any).Misconfigurations) ? (r as any).Misconfigurations.length : 0
          const s = Array.isArray((r as any).Secrets) ? (r as any).Secrets.length : 0
          total += v + m + s
        }
        return total
      }
      case 'zap': {
        // zap baseline JSON: { site: [ { alerts: [] } ] }
        const sites = Array.isArray((parsed as any).site) ? (parsed as any).site : []
        let total = 0
        for (const s of sites) {
          const alerts = Array.isArray((s as any).alerts) ? (s as any).alerts.length : 0
          total += alerts
        }
        return total
      }
      case 'noir': {
        // noir generic: { findings: [] }
        const findings = Array.isArray((parsed as any).findings) ? (parsed as any).findings : []
        return findings.length
      }
      default:
        return 0
    }
  } catch {
    return 0
  }
}

function ensureApiUrl(base: string): string {
  const noTrail = base.endsWith('/') ? base.slice(0, -1) : base
  return `${noTrail}/api/v2`
}

async function ddFetch<T>(opts: { url: string; apiKey: string; init?: RequestInit }): Promise<{ status: number; json: T | null; text: string }> {
  const headers = new Headers(opts.init?.headers ?? {})
  headers.set('Authorization', `Token ${opts.apiKey}`)
  const res = await fetch(opts.url, { ...opts.init, headers })
  const text = await res.text()
  let json: T | null = null
  try {
    json = text ? (JSON.parse(text) as T) : null
  } catch {
    json = null
  }
  return { status: res.status, json, text }
}

type DDListResponse<T> = {
  count: number
  next: string | null
  previous: string | null
  results: T[]
}
type DDEngagement = { id: number; name: string; product: number }
type DDProduct = { id: number; name: string }
type DDTest = { id: number; title?: string; test_type?: number; test_type_name?: string; target_start?: string; engagement: number }
type DDFinding = { id: number; active: boolean; duplicate: boolean; engagement: number }

async function resolveEngagementId(
  ddBase: string,
  apiKey: string,
  productName: string | undefined,
  engagementName: string
): Promise<number | undefined> {
  let productId: number | undefined
  if (productName) {
    let url = `${ddBase}/products/?name=${encodeURIComponent(productName)}`
    let found: DDProduct | undefined
    while (url) {
      const { json, status } = await ddFetch<DDListResponse<DDProduct>>({ url, apiKey })
      if (status >= 400 || !json) break
      found = json.results.find((p) => p.name.toLowerCase() === productName.toLowerCase()) || json.results[0]
      if (found) break
      url = json.next || ''
    }
    productId = found?.id
  }
  let engUrl = `${ddBase}/engagements/?name=${encodeURIComponent(engagementName)}${productId ? `&product=${productId}` : ''}`
  while (engUrl) {
    const { json, status } = await ddFetch<DDListResponse<DDEngagement>>({ url: engUrl, apiKey })
    if (status >= 400 || !json) break
    const found = json.results.find((e) => e.name.toLowerCase() === engagementName.toLowerCase() && (!productId || e.product === productId))
    if (found) return found.id
    engUrl = json.next || ''
  }
  return undefined
}

async function validateInDefectDojo(opts: Options, summary: PipelineSummary): Promise<void> {
  if (!opts.ddUrl || !opts.apiKey) {
    summary.warnings.push('DefectDojo URL/API key not provided; skipping validation.')
    return
  }
  let engagementId = opts.engagementId
  const ddBase = ensureApiUrl(opts.ddUrl)
  if (!engagementId) {
    if (!opts.engagementName) {
      summary.warnings.push('Engagement not specified; cannot validate in DefectDojo.')
      return
    }
    engagementId = await resolveEngagementId(ddBase, opts.apiKey, opts.productName, opts.engagementName)
  }
  if (!engagementId) {
    summary.warnings.push('Could not resolve engagement; skipping validation.')
    return
  }

  // Fetch tests for engagement
  const testsResp = await ddFetch<DDListResponse<DDTest>>({
    url: `${ddBase}/tests/?engagement=${engagementId}&limit=1000&ordering=-target_start`,
    apiKey: opts.apiKey!,
  })
  let tests: DDTest[] = []
  if (testsResp.status < 400 && testsResp.json) {
    tests = testsResp.json.results
  } else {
    summary.warnings.push(`Failed to list tests: HTTP ${testsResp.status}`)
  }

  // Fetch findings for engagement
  const findingsResp = await ddFetch<DDListResponse<DDFinding>>({
    url: `${ddBase}/findings/?engagement=${engagementId}&limit=1000`,
    apiKey: opts.apiKey!,
  })
  let findings: DDFinding[] = []
  if (findingsResp.status < 400 && findingsResp.json) {
    findings = findingsResp.json.results
  } else {
    summary.warnings.push(`Failed to list findings: HTTP ${findingsResp.status}`)
  }

  summary.validation = {
    engagementId,
    testsCount: tests.length,
    tests: tests.map((t) => ({ id: t.id, title: t.title, typeName: (t as any).test_type_name, targetStart: t.target_start })),
    findingsActive: findings.filter((f) => f.active).length,
    findingsDuplicate: findings.filter((f) => f.duplicate).length,
    info:
      'Validation pulls current engagement tests and findings. Exact per-tool mapping may vary depending on DefectDojo configuration and deduplication.',
  }
}

async function main() {
  const started = new Date()
  const opts = parseOptions()
  await ensureDir(opts.outDir)

  const summary: PipelineSummary = {
    run: {
      startedAt: started.toISOString(),
      finishedAt: '',
      outDir: opts.outDir,
      zapTarget: opts.zapTarget,
    },
    reports: [],
    uploads: [],
    warnings: [],
  }

  // 1) Execute security scan
  console.log('=== [1/3] Running security scans ===')
  const scanBin = tsxBin()
  const scan = await runCmd(scanBin, scanArgs(opts), process.cwd())
  if (scan.code !== 0) {
    summary.warnings.push(`Scan script returned ${scan.code}. Continuing.`)
    console.warn(scan.stderr || scan.stdout)
  }

  // 2) Collect report stats
  console.log('=== Collecting report stats ===')
  const presentTools: ToolKey[] = (Object.keys(FILES) as ToolKey[]).filter((k) =>
    existsSync(resolve(opts.outDir, FILES[k]))
  )
  for (const key of presentTools) {
    const report = resolve(opts.outDir, FILES[key])
    const found = countFindingsForReport(key, report)
    summary.reports.push({ key, report, found })
  }

  // 3) Upload to DefectDojo
  console.log('=== [2/3] Uploading reports to DefectDojo ===')
  const uploadBin = tsxBin()
  const upload = await runCmd(uploadBin, uploadArgs(opts), process.cwd())
  if (upload.code !== 0) {
    summary.warnings.push(`Upload script returned ${upload.code}. Some or all uploads may have failed.`)
  }
  // Parse "Upload Summary" from stdout if available
  const upLines = (upload.stdout || '').split('\n').map((s) => s.trim())
  const idx = upLines.findIndex((l) => l.toLowerCase().includes('upload summary'))
  if (idx >= 0) {
    const lines = upLines.slice(idx + 1)
    for (const line of lines) {
      if (!line.startsWith('-')) continue
      // Format: - <Tool> OK/ERR  <file>  (status)
      const parts = line.replace(/^\-\s*/, '').split(/\s{2,}/)
      const toolTitle = parts[0]?.trim() || ''
      const ok = (parts[1] || '').startsWith('OK')
      const file = parts[2]?.trim()
      const statusMatch = line.match(/\((\d{3})\)/)
      const status = statusMatch ? Number(statusMatch[1]) : undefined
      // map toolTitle back to key
      const key = (Object.keys(TOOL_TITLES) as ToolKey[]).find((k) => TOOL_TITLES[k] === toolTitle)
      if (key) {
        summary.uploads.push({ key, ok, file, status, error: ok ? undefined : 'upload failed' })
      }
    }
  } else {
    summary.warnings.push('Could not parse upload summary from uploader output.')
  }

  // 4) Validate in DefectDojo
  console.log('=== [3/3] Validating results in DefectDojo ===')
  await validateInDefectDojo(opts, summary)

  // 5) Write summary artifact
  const finished = new Date()
  summary.run.finishedAt = finished.toISOString()
  const artifactPath = resolve(opts.outDir, 'run_summary.json')
  writeFileSync(artifactPath, JSON.stringify(summary, null, 2), 'utf8')

  // Console summary
  console.log('\n=== Run Summary ===')
  console.log(`Reports dir: ${opts.outDir}`)
  for (const r of summary.reports) {
    console.log(`- ${TOOL_TITLES[r.key].padEnd(22)} findings: ${r.found.toString().padStart(3)}  -> ${r.report}`)
  }
  if (summary.uploads.length > 0) {
    console.log('\nUpload status:')
    for (const u of summary.uploads) {
      console.log(`- ${TOOL_TITLES[u.key].padEnd(22)} ${u.ok ? 'OK ' : 'ERR'}  ${u.file ?? ''} ${u.status ? `(${u.status})` : ''}`)
    }
  }
  if (summary.validation) {
    console.log('\nDefectDojo engagement validation:')
    console.log(
      `- Engagement #${summary.validation.engagementId} has ${summary.validation.testsCount} test(s), Active findings: ${summary.validation.findingsActive}, Duplicates: ${summary.validation.findingsDuplicate}`
    )
    if (summary.validation.tests && summary.validation.tests.length > 0) {
      const recent = summary.validation.tests.slice(0, 10)
      for (const t of recent) {
        console.log(`  • Test #${t.id} ${t.typeName ? `[${t.typeName}]` : ''} ${t.title ? `- ${t.title}` : ''}`)
      }
    }
  }
  if (summary.warnings.length > 0) {
    console.warn('\nWarnings:')
    for (const w of summary.warnings) console.warn(`- ${w}`)
  }

  // Exit behavior
  if (opts.strict) {
    // Fail if any upload failed or DD validation failed to fetch
    const anyUploadErr = summary.uploads.some((u) => !u.ok)
    const noValidation = !summary.validation
    process.exit(anyUploadErr || noValidation ? 2 : 0)
  } else {
    process.exit(0)
  }
}

main().catch((e) => {
  console.error('Pipeline crashed:', e)
  process.exit(1)
})
