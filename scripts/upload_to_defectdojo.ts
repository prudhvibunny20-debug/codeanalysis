/* eslint-disable no-console */

import { promises as fs } from 'node:fs'
import { existsSync } from 'node:fs'
import { basename, resolve } from 'node:path'

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

type UploadPlan = {
  key: ToolKey
  file: string
  scanType: string
  testTitle: string
}

type UploadResult = {
  key: ToolKey
  ok: boolean
  status: number
  detail?: string
  error?: string
  file?: string
}

type Options = {
  ddUrl: string
  apiKey: string
  outDir: string
  productName?: string
  engagementName?: string
  engagementId?: number
  branchTag?: string
  commitHash?: string
  buildId?: string
  minimumSeverity: 'Info' | 'Low' | 'Medium' | 'High' | 'Critical'
  closeOldFindings: boolean
  active: boolean
  verified: boolean
  strict: boolean
  createTestTitleSuffix?: string
}

const DEFAULT_OUTDIR = resolve(process.cwd(), 'security-reports')

// Known scan type labels in DefectDojo
const SCAN_TYPES: Record<ToolKey, string> = {
  semgrep: 'Semgrep JSON Report',
  codeql: 'SARIF',
  gitleaks: 'Gitleaks Scan',
  syft: 'CycloneDX',
  osv: 'OSV Scanner',
  kics: 'KICS Scan',
  trivy: 'Trivy',
  zap: 'ZAP Baseline Scan',
  noir: 'Generic Findings Import',
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

function readFlag(name: string): string | undefined {
  const idx = process.argv.indexOf(`--${name}`)
  if (idx >= 0 && idx < process.argv.length - 1) return process.argv[idx + 1]
  return undefined
}

function readBoolFlag(name: string): boolean {
  return process.argv.includes(`--${name}`)
}

function toBooleanLike(val: string | undefined, defaultVal: boolean): boolean {
  if (typeof val !== 'string') return defaultVal
  const v = val.toLowerCase()
  if (v === 'true' || v === '1' || v === 'yes') return true
  if (v === 'false' || v === '0' || v === 'no') return false
  return defaultVal
}

function parseOptions(): Options {
  const ddUrl = readFlag('dd-url') || process.env.DD_URL || process.env.DEFECTDOJO_URL || ''
  const apiKey = readFlag('api-key') || process.env.DD_API_KEY || process.env.DEFECTDOJO_API_KEY || ''
  const outDir = readFlag('out-dir') || process.env.SECURITY_SCAN_OUT_DIR || DEFAULT_OUTDIR
  const productName = readFlag('product-name') || process.env.DD_PRODUCT_NAME
  const engagementName = readFlag('engagement-name') || process.env.DD_ENGAGEMENT_NAME
  const engagementIdRaw = readFlag('engagement-id') || process.env.DD_ENGAGEMENT_ID
  const branchTag = readFlag('branch') || process.env.CI_BRANCH || process.env.GIT_BRANCH
  const commitHash = readFlag('commit') || process.env.CI_COMMIT_SHA || process.env.GIT_COMMIT || process.env.COMMIT_SHA
  const buildId = readFlag('build-id') || process.env.CI_BUILD_ID || process.env.BUILD_ID || process.env.GITHUB_RUN_ID
  const minimumSeverity = (readFlag('min-severity') || process.env.DD_MIN_SEVERITY || 'Info') as Options['minimumSeverity']
  const closeOldFindings = toBooleanLike(readFlag('close-old'), false)
  const active = toBooleanLike(readFlag('active') || process.env.DD_ACTIVE, true)
  const verified = toBooleanLike(readFlag('verified') || process.env.DD_VERIFIED, true)
  const strict = readBoolFlag('strict') || toBooleanLike(process.env.DD_STRICT, false)
  const createTestTitleSuffix = readFlag('title-suffix') || process.env.DD_TEST_TITLE_SUFFIX

  const engagementId = engagementIdRaw ? Number(engagementIdRaw) : undefined

  if (!ddUrl || !apiKey) {
    console.error('Missing DefectDojo URL or API key. Provide --dd-url and --api-key or set DD_URL/DEFECTDOJO_URL and DD_API_KEY/DEFECTDOJO_API_KEY.')
  }

  return {
    ddUrl,
    apiKey,
    outDir: resolve(outDir),
    productName,
    engagementName,
    engagementId,
    branchTag,
    commitHash,
    buildId,
    minimumSeverity,
    closeOldFindings,
    active,
    verified,
    strict,
    createTestTitleSuffix,
  }
}

function ensureApiUrl(base: string): string {
  const noTrail = base.endsWith('/') ? base.slice(0, -1) : base
  return `${noTrail}/api/v2`
}

async function ddFetch<T>(opts: { url: string; apiKey: string; init?: RequestInit }): Promise<{ status: number; data: T | null; text: string }> {
  const headers = new Headers(opts.init?.headers ?? {})
  headers.set('Authorization', `Token ${opts.apiKey}`)
  if (!headers.has('Content-Type') && (opts.init?.method ?? 'GET') !== 'GET') {
    // For JSON requests
    headers.set('Content-Type', 'application/json')
  }
  const res = await fetch(opts.url, { ...opts.init, headers })
  const text = await res.text()
  let data: T | null = null
  try {
    data = text ? (JSON.parse(text) as T) : (null as T | null)
  } catch {
    data = null
  }
  return { status: res.status, data, text }
}

type DDListResponse<T> = {
  count: number
  next: string | null
  previous: string | null
  results: T[]
}

type DDProduct = { id: number; name: string }
type DDEngagement = { id: number; name: string; product: number }

async function findProductIdByName(ddBase: string, apiKey: string, name: string): Promise<number | undefined> {
  let url = `${ddBase}/products/?name=${encodeURIComponent(name)}`
  while (url) {
    const { status, data } = await ddFetch<DDListResponse<DDProduct>>({ url, apiKey })
    if (status >= 400 || !data) break
    const found = data.results.find((p) => p.name.toLowerCase() === name.toLowerCase())
    if (found) return found.id
    url = data.next ?? ''
  }
  // Fallback: try __icontains
  url = `${ddBase}/products/?name__icontains=${encodeURIComponent(name)}`
  const resp = await ddFetch<DDListResponse<DDProduct>>({ url, apiKey })
  if (resp.status < 400 && resp.data) {
    const found = resp.data.results.find((p) => p.name.toLowerCase() === name.toLowerCase()) || resp.data.results[0]
    return found?.id
  }
  return undefined
}

async function findEngagementId(ddBase: string, apiKey: string, productId: number | undefined, engagementName: string): Promise<number | undefined> {
  let url = `${ddBase}/engagements/?name=${encodeURIComponent(engagementName)}`
  if (productId) url += `&product=${productId}`
  while (url) {
    const { status, data } = await ddFetch<DDListResponse<DDEngagement>>({ url, apiKey })
    if (status >= 400 || !data) break
    const found = data.results.find(
      (e) => e.name.toLowerCase() === engagementName.toLowerCase() && (!productId || e.product === productId)
    )
    if (found) return found.id
    url = data.next ?? ''
  }
  // Fallback contains
  url = `${ddBase}/engagements/?name__icontains=${encodeURIComponent(engagementName)}${productId ? `&product=${productId}` : ''}`
  const resp = await ddFetch<DDListResponse<DDEngagement>>({ url, apiKey })
  if (resp.status < 400 && resp.data) {
    const found = resp.data.results.find((e) => (!productId || e.product === productId))
    return found?.id
  }
  return undefined
}

function ymd(date: Date): string {
  const y = date.getFullYear()
  const m = `${date.getMonth() + 1}`.padStart(2, '0')
  const d = `${date.getDate()}`.padStart(2, '0')
  return `${y}-${m}-${d}`
}

async function uploadOne(
  ddBase: string,
  apiKey: string,
  engagementId: number,
  plan: UploadPlan,
  opts: Options
): Promise<UploadResult> {
  const filePath = resolve(opts.outDir, plan.file)
  if (!existsSync(filePath)) {
    return { key: plan.key, ok: false, status: 0, error: 'file not found', file: filePath }
  }

  try {
    const buf = await fs.readFile(filePath)
    const blob = new Blob([buf], { type: 'application/octet-stream' })

    const form = new FormData()
    form.set('engagement', String(engagementId))
    form.set('scan_type', plan.scanType)
    form.set('file', blob, basename(filePath))
    form.set('active', String(opts.active))
    form.set('verified', String(opts.verified))
    form.set('minimum_severity', opts.minimumSeverity)
    form.set('close_old_findings', String(opts.closeOldFindings))
    form.set('scan_date', ymd(new Date()))
    form.set('test_title', opts.createTestTitleSuffix ? `${plan.testTitle} - ${opts.createTestTitleSuffix}` : plan.testTitle)
    if (opts.branchTag) form.set('branch_tag', opts.branchTag)
    if (opts.commitHash) form.set('commit_hash', opts.commitHash)
    if (opts.buildId) form.set('build_id', opts.buildId)

    const url = `${ddBase}/reimport-scan/`
    const headers = new Headers()
    headers.set('Authorization', `Token ${apiKey}`)

    const res = await fetch(url, {
      method: 'POST',
      body: form,
      headers,
    })

    const text = await res.text()
    const ok = res.status >= 200 && res.status < 300
    if (!ok) {
      return { key: plan.key, ok: false, status: res.status, error: text || 'upload failed', file: filePath }
    }
    return { key: plan.key, ok: true, status: res.status, detail: text, file: filePath }
  } catch (e) {
    return { key: plan.key, ok: false, status: 0, error: String(e), file: filePath }
  }
}

function buildPlan(outDir: string): UploadPlan[] {
  const entries: UploadPlan[] = (Object.keys(FILES) as ToolKey[]).map((key) => ({
    key,
    file: FILES[key],
    scanType: SCAN_TYPES[key],
    testTitle: TOOL_TITLES[key],
  }))
  // Only include those whose files exist in outDir
  return entries.filter((e) => existsSync(resolve(outDir, e.file)))
}

async function main() {
  const opts = parseOptions()
  if (!opts.ddUrl || !opts.apiKey) {
    console.error('DefectDojo URL or API key missing; aborting upload.')
    process.exit(1)
  }
  const ddBase = ensureApiUrl(opts.ddUrl)

  // Resolve engagement id if not directly specified
  let engagementId = opts.engagementId
  if (!engagementId) {
    if (!opts.engagementName) {
      console.error('Missing engagement identifier. Provide --engagement-id or --engagement-name (optionally with --product-name).')
      process.exit(1)
    }
    let productId: number | undefined
    if (opts.productName) {
      console.log(`Resolving product "${opts.productName}"...`)
      productId = await findProductIdByName(ddBase, opts.apiKey, opts.productName)
      if (!productId) {
        console.error(`Product "${opts.productName}" not found.`)
        process.exit(1)
      }
    }
    console.log(`Resolving engagement "${opts.engagementName}"...`)
    const eid = await findEngagementId(ddBase, opts.apiKey, productId, opts.engagementName)
    if (!eid) {
      console.error(`Engagement "${opts.engagementName}" not found${productId ? ` under product ${opts.productName}` : ''}.`)
      process.exit(1)
    }
    engagementId = eid
  }

  const plan = buildPlan(opts.outDir)
  if (plan.length === 0) {
    console.warn(`No reports found in ${opts.outDir}. Nothing to upload.`)
    process.exit(0)
  }

  console.log(`Uploading ${plan.length} report(s) to DefectDojo engagement #${engagementId}...`)

  const results: UploadResult[] = []
  for (const p of plan) {
    console.log(`→ ${TOOL_TITLES[p.key]} (${p.scanType}) from ${p.file}`)
    const r = await uploadOne(ddBase, opts.apiKey, engagementId, p, opts)
    if (r.ok) {
      console.log(`  ✓ Uploaded (${r.status})`)
    } else {
      console.warn(`  ! Failed (${r.status}): ${r.error ?? 'Unknown error'}`)
    }
    results.push(r)
  }

  console.log('\nUpload Summary:')
  for (const r of results) {
    console.log(
      `- ${TOOL_TITLES[r.key].padEnd(22)} ${r.ok ? 'OK ' : 'ERR'}  ${r.file ?? ''}  ${r.ok ? '' : `(${r.status})`}`
    )
  }

  const failed = results.filter((r) => !r.ok).length
  if (failed > 0) {
    console.warn(`\nCompleted with ${failed} upload failure(s).`)
    if (opts.strict) {
      process.exit(2)
    }
  } else {
    console.log('\nAll uploads succeeded.')
  }
}

main().catch((e) => {
  console.error('Upload script crashed:', e)
  process.exit(1)
})
