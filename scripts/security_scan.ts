/* eslint-disable no-console */

import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, readdirSync, renameSync, writeFileSync } from 'node:fs'
import { promises as fs } from 'node:fs'
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

type RunResult = {
  tool: ToolKey
  ok: boolean
  output?: string
  error?: string
}

type Options = {
  outDir: string
  zapTarget?: string
  enabled: Partial<Record<ToolKey, boolean>>
}

const DEFAULT_OUTDIR = resolve(process.cwd(), 'security-reports')

const TOOL_LABELS: Record<ToolKey, string> = {
  semgrep: 'Semgrep',
  codeql: 'CodeQL',
  gitleaks: 'Gitleaks',
  syft: 'Syft',
  osv: 'osv-scanner',
  kics: 'KICS',
  trivy: 'Trivy',
  zap: 'OWASP ZAP',
  noir: 'Noir',
}

function readFlag(name: string): string | undefined {
  const idx = process.argv.indexOf(`--${name}`)
  if (idx >= 0 && idx < process.argv.length - 1) {
    return process.argv[idx + 1]
  }
  return undefined
}

function readBoolFlag(name: string): boolean | undefined {
  const idx = process.argv.indexOf(`--${name}`)
  if (idx >= 0) return true
  return undefined
}

function parseOptions(): Options {
  const outDir = readFlag('out-dir') || process.env.SECURITY_SCAN_OUT_DIR || DEFAULT_OUTDIR
  const zapTarget = readFlag('zap-target') || process.env.ZAP_TARGET || process.env.ZAP_BASELINE_TARGET
  const enabled: Partial<Record<ToolKey, boolean>> = {}

  const tools: ToolKey[] = ['semgrep', 'codeql', 'gitleaks', 'syft', 'osv', 'kics', 'trivy', 'zap', 'noir']
  for (const tool of tools) {
    const upper = tool.toUpperCase()
    const envVal = process.env[`ENABLE_${upper}`]
    const flagVal = readBoolFlag(`enable-${tool}`)
    const flagDisable = readBoolFlag(`disable-${tool}`)
    if (flagDisable) {
      enabled[tool] = false
    } else if (flagVal) {
      enabled[tool] = true
    } else if (typeof envVal === 'string') {
      enabled[tool] = envVal === '1' || envVal.toLowerCase() === 'true'
    }
  }

  return { outDir, zapTarget, enabled }
}

async function ensureDir(dir: string) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
}

function run(cmd: string, args: string[], cwd: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolvePromise) => {
    const child = spawn(cmd, args, { cwd, env: process.env })
    const chunksOut: Buffer[] = []
    const chunksErr: Buffer[] = []
    child.stdout.on('data', (d: Buffer) => chunksOut.push(d))
    child.stderr.on('data', (d: Buffer) => chunksErr.push(d))
    child.on('close', (code: number) => {
      resolvePromise({
        code: code ?? 1,
        stdout: Buffer.concat(chunksOut).toString('utf8'),
        stderr: Buffer.concat(chunksErr).toString('utf8'),
      })
    })
    child.on('error', (err: Error) => {
      resolvePromise({ code: 127, stdout: '', stderr: err.message })
    })
  })
}

async function commandExists(binary: string): Promise<boolean> {
  const result = await run(binary, ['--version'], process.cwd())
  // Some tools use non-zero exit on --version; fallback to checking ENOENT by stderr
  const notFound = result.code === 127 || /not\s*found|ENOENT/i.test(result.stderr)
  return !notFound
}

function writeJson(outPath: string, data: unknown) {
  const content = JSON.stringify(data, null, 2)
  writeFileSync(outPath, content, 'utf8')
}

function logHeader(title: string) {
  const line = '-'.repeat(Math.max(8, title.length + 6))
  console.log(`\n${line}\n>>> ${title}\n${line}`)
}

async function runSemgrep(outDir: string): Promise<RunResult> {
  const tool: ToolKey = 'semgrep'
  const out = join(outDir, 'semgrep_report.json')
  try {
    if (!(await commandExists('semgrep'))) {
      writeJson(out, {
        results: [],
        errors: [],
        paths: { scanned: [], skipped: [] },
        version: '0.0.0',
        note: 'Semgrep CLI not found; generated empty placeholder.',
      })
      return { tool, ok: false, output: out, error: 'semgrep not found' }
    }
    console.log('Running semgrep scan...')
    const args = [
      'scan',
      '--config',
      'p/ci',
      '--json',
      '--output',
      out,
      '--skip-unknown-extensions',
      '--exclude',
      'node_modules',
      '--exclude',
      '.git',
      '--exclude',
      'dist',
      '--exclude',
      'build',
      '.',
    ]
    const res = await run('semgrep', args, process.cwd())
    if (res.code !== 0) {
      console.warn('Semgrep returned non-zero exit:', res.code)
    }
    if (!existsSync(out)) {
      // Fallback: if CLI wrote to stdout, capture
      if (res.stdout.trim().startsWith('{')) {
        writeFileSync(out, res.stdout, 'utf8')
      } else {
        writeJson(out, { results: [], errors: [{ message: 'No output produced' }] })
      }
    }
    return { tool, ok: true, output: out }
  } catch (e) {
    writeJson(out, { results: [], errors: [{ message: String(e) }] })
    return { tool, ok: false, output: out, error: String(e) }
  }
}

async function runCodeQL(outDir: string): Promise{ tool: ToolKey; ok: boolean; output?: string; error?: string } {
  const tool: ToolKey = 'codeql'
  const sarifPath = join(outDir, 'codeql_report.sarif')
  try {
    if (!(await commandExists('codeql'))) {
      // minimal SARIF
      writeJson(sarifPath, {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [],
        note: 'CodeQL CLI not found; generated empty SARIF placeholder.',
      })
      return { tool, ok: false, output: sarifPath, error: 'codeql not found' }
    }
    console.log('Running CodeQL database create...')
    const dbPath = join(outDir, 'codeql-db')
    const create = await run('codeql', ['database', 'create', dbPath, '--language=javascript', '--source-root', '.'], process.cwd())
    if (create.code !== 0) {
      console.warn('CodeQL database create returned:', create.code, create.stderr)
    }
    console.log('Running CodeQL analyze...')
    const analyze = await run(
      'codeql',
      ['database', 'analyze', dbPath, 'javascript-code-scanning.qls', '--format=sarifv2.1.0', '--output', sarifPath],
      process.cwd()
    )
    if (analyze.code !== 0) {
      console.warn('CodeQL analyze returned:', analyze.code, analyze.stderr)
    }
    if (!existsSync(sarifPath)) {
      // fallback empty SARIF
      writeJson(sarifPath, {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [],
      })
    }
    return { tool, ok: true, output: sarifPath }
  } catch (e) {
    writeJson(sarifPath, {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [],
      error: String(e),
    })
    return { tool, ok: false, output: sarifPath, error: String(e) }
  }
}

async function runGitleaks(outDir: string): Promise<RunResult> {
  const tool: ToolKey = 'gitleaks'
  const out = join(outDir, 'gitleaks_report.json')
  try {
    if (!(await commandExists('gitleaks'))) {
      writeJson(out, [])
      return { tool, ok: false, output: out, error: 'gitleaks not found' }
    }
    console.log('Running Gitleaks...')
    const res = await run(
      'gitleaks',
      ['detect', '--source', '.', '--report-format', 'json', '--report-path', out, '--no-banner', '--scan-history'],
      process.cwd()
    )
    if (res.code !== 0) console.warn('Gitleaks returned:', res.code)
    if (!existsSync(out)) {
      // CLI might output to stdout
      if (res.stdout.trim().startsWith('[')) {
        writeFileSync(out, res.stdout, 'utf8')
      } else {
        writeJson(out, [])
      }
    }
    return { tool, ok: true, output: out }
  } catch (e) {
    writeJson(out, [])
    return { tool, ok: false, output: out, error: String(e) }
  }
}

async function runSyft(outDir: string): Promise<RunResult> {
  const tool: ToolKey = 'syft'
  const out = join(outDir, 'sbom.cdx.json')
  try {
    if (!(await commandExists('syft'))) {
      writeJson(out, { bomFormat: 'CycloneDX', specVersion: '1.4', version: 1, components: [], note: 'syft not found (placeholder)' })
      return { tool, ok: false, output: out, error: 'syft not found' }
    }
    console.log('Generating SBOM with Syft...')
    const res = await run('syft', ['dir:.', '-o', 'cyclonedx-json', '--file', out], process.cwd())
    if (res.code !== 0) console.warn('Syft returned:', res.code, res.stderr)
    if (!existsSync(out)) {
      writeJson(out, { bomFormat: 'CycloneDX', specVersion: '1.4', version: 1, components: [] })
    }
    return { tool, ok: true, output: out }
  } catch (e) {
    writeJson(out, { bomFormat: 'CycloneDX', specVersion: '1.4', version: 1, components: [], error: String(e) })
    return { tool, ok: false, output: out, error: String(e) }
  }
}

async function runOSV(outDir: string, sbomPath: string): Promise<RunResult> {
  const tool: ToolKey = 'osv'
  const out = join(outDir, 'osv_report.json')
  try {
    if (!(await commandExists('osv-scanner'))) {
      writeJson(out, { results: [], note: 'osv-scanner not found (placeholder)' })
      return { tool, ok: false, output: out, error: 'osv-scanner not found' }
    }
    console.log('Running osv-scanner using SBOM...')
    const res = await run('osv-scanner', ['--format', 'json', '--sbom', sbomPath, '--output', out], process.cwd())
    if (res.code !== 0) console.warn('osv-scanner returned:', res.code)
    if (!existsSync(out)) {
      if (res.stdout.trim().startsWith('{')) writeFileSync(out, res.stdout, 'utf8')
      else writeJson(out, { results: [] })
    }
    return { tool, ok: true, output: out }
  } catch (e) {
    writeJson(out, { results: [], error: String(e) })
    return { tool, ok: false, output: out, error: String(e) }
  }
}

async function runKICS(outDir: string): Promise<RunResult> {
  const tool: ToolKey = 'kics'
  const desired = join(outDir, 'kics_report.json')
  try {
    if (!(await commandExists('kics'))) {
      writeJson(desired, { queries: [], files: [], version: 'placeholder', note: 'kics not found (placeholder)' })
      return { tool, ok: false, output: desired, error: 'kics not found' }
    }
    console.log('Running KICS...')
    const res = await run('kics', ['scan', '-p', '.', '-o', outDir, '-f', 'json', '-s'], process.cwd())
    if (res.code !== 0) console.warn('KICS returned:', res.code)
    // Find produced json in outDir
    const files = readdirSync(outDir).filter((f) => f.toLowerCase().endsWith('.json'))
    const kicsCandidate = files.find((f) => f.toLowerCase().includes('kics')) || files.find((f) => f.toLowerCase().includes('result'))
    if (kicsCandidate && kicsCandidate !== 'kics_report.json') {
      renameSync(join(outDir, kicsCandidate), desired)
    }
    if (!existsSync(desired)) {
      // last resort, create empty structure
      writeJson(desired, { queries: [], files: [] })
    }
    return { tool, ok: true, output: desired }
  } catch (e) {
    writeJson(desired, { queries: [], files: [], error: String(e) })
    return { tool, ok: false, output: desired, error: String(e) }
  }
}

async function runTrivy(outDir: string): Promise<RunResult> {
  const tool: ToolKey = 'trivy'
  const out = join(outDir, 'trivy_report.json')
  try {
    if (!(await commandExists('trivy'))) {
      writeJson(out, { Results: [], note: 'trivy not found (placeholder)' })
      return { tool, ok: false, output: out, error: 'trivy not found' }
    }
    console.log('Running Trivy FS scan (vuln,secret,config)...')
    const res = await run('trivy', ['fs', '--format', 'json', '--scanners', 'vuln,secret,config', '--output', out, '.'], process.cwd())
    if (res.code !== 0) console.warn('Trivy returned:', res.code)
    if (!existsSync(out)) {
      if (res.stdout.trim().startsWith('{')) writeFileSync(out, res.stdout, 'utf8')
      else writeJson(out, { Results: [] })
    }
    return { tool, ok: true, output: out }
  } catch (e) {
    writeJson(out, { Results: [], error: String(e) })
    return { tool, ok: false, output: out, error: String(e) }
  }
}

async function runZAP(outDir: string, target?: string): Promise<RunResult> {
  const tool: ToolKey = 'zap'
  const out = join(outDir, 'zap_report.json')
  try {
    if (!target) {
      writeJson(out, { site: [], note: 'No ZAP target specified; set --zap-target or ZAP_TARGET.' })
      return { tool, ok: false, output: out, error: 'missing target' }
    }
    // Try zap-baseline.py, if unavailable create placeholder
    const hasZap = await commandExists('zap-baseline.py')
    if (!hasZap) {
      writeJson(out, { site: [], target, note: 'zap-baseline.py not found (placeholder)' })
      return { tool, ok: false, output: out, error: 'zap-baseline.py not found' }
    }
    console.log('Running OWASP ZAP Baseline...')
    const res = await run('zap-baseline.py', ['-t', target, '-J', out, '-I'], process.cwd())
    if (res.code !== 0) console.warn('ZAP returned:', res.code)
    if (!existsSync(out)) {
      writeJson(out, { site: [], target, stderr: res.stderr })
    }
    return { tool, ok: true, output: out }
  } catch (e) {
    writeJson(out, { site: [], target, error: String(e) })
    return { tool, ok: false, output: out, error: String(e) }
  }
}

async function runNoir(outDir: string): Promise<RunResult> {
  const tool: ToolKey = 'noir'
  const outNative = join(outDir, 'noir_report.json')
  const outGeneric = join(outDir, 'noir_generic.json')
  try {
    let nativeOk = false
    if (await commandExists('noir')) {
      console.log('Running Noir...')
      const res = await run('noir', ['scan', '.', '--output', outNative], process.cwd())
      if (res.code !== 0) console.warn('Noir returned:', res.code)
      nativeOk = existsSync(outNative)
      if (!nativeOk) {
        // if noir printed to stdout
        if (res.stdout.trim().startsWith('{') || res.stdout.trim().startsWith('[')) {
          writeFileSync(outNative, res.stdout, 'utf8')
          nativeOk = true
        }
      }
    }
    if (!nativeOk) {
      // placeholder native output
      writeJson(outNative, { findings: [], note: 'noir not found (placeholder)' })
    }

    // Preprocess to DefectDojo Generic Findings JSON
    try {
      const raw = await fs.readFile(outNative, 'utf8')
      const parsed = JSON.parse(raw) as unknown
      const findings = normalizeNoirToGeneric(parsed)
      writeJson(outGeneric, { findings })
    } catch (e) {
      // If parse fails, still produce empty generic report
      writeJson(outGeneric, { findings: [], error: String(e) })
    }

    return { tool, ok: nativeOk, output: outGeneric, error: nativeOk ? undefined : 'noir not found' }
  } catch (e) {
    writeJson(outGeneric, { findings: [], error: String(e) })
    return { tool, ok: false, output: outGeneric, error: String(e) }
  }
}

type GenericFinding = {
  title: string
  description: string
  severity: 'Info' | 'Low' | 'Medium' | 'High' | 'Critical'
  file_path?: string
  line?: number
  cwe?: number
  references?: string
  vuln_id_from_tool?: string
}

function normalizeNoirToGeneric(parsed: unknown): GenericFinding[] {
  // This is a best-effort normalizer; adjust once Noir schema is known.
  // Accept either { findings: [...] } or plain array
  const now = Date.now()
  const arr: any[] =
    Array.isArray(parsed)
      ? parsed
      : typeof parsed === 'object' && parsed !== null && Array.isArray((parsed as any).findings)
        ? (parsed as any).findings
        : []
  const mapSeverity = (s: string | undefined): GenericFinding['severity'] => {
    const v = (s || '').toLowerCase()
    if (v.includes('critical')) return 'Critical'
    if (v.includes('high')) return 'High'
    if (v.includes('medium')) return 'Medium'
    if (v.includes('low')) return 'Low'
    return 'Info'
    }
  return arr.map((f, i): GenericFinding => {
    const title = typeof f.title === 'string' && f.title.length > 0 ? f.title : `Noir Finding ${i + 1}`
    const description = typeof f.description === 'string' ? f.description : JSON.stringify(f, null, 2)
    const severity = mapSeverity(typeof f.severity === 'string' ? f.severity : undefined)
    const filePath = typeof f.file === 'string' ? f.file : typeof f.file_path === 'string' ? f.file_path : undefined
    const line = typeof f.line === 'number' ? f.line : undefined
    const cwe = typeof f.cwe === 'number' ? f.cwe : undefined
    const vulnId = typeof f.id === 'string' ? f.id : typeof f.ruleId === 'string' ? f.ruleId : undefined
    const refs = typeof f.references === 'string' ? f.references : Array.isArray(f.references) ? (f.references as string[]).join('\n') : undefined
    return {
      title,
      description,
      severity,
      file_path: filePath,
      line,
      cwe,
      vuln_id_from_tool: vulnId,
      references: refs ?? `Generated: ${new Date(now).toISOString()}`,
    }
  })
}

async function main() {
  const opts = parseOptions()
  const outDir = resolve(opts.outDir)
  await ensureDir(outDir)

  logHeader('Security Scanning - Execution and Report Generation')

  const enableDefault: Record<ToolKey, boolean> = {
    semgrep: true,
    codeql: true,
    gitleaks: true,
    syft: true,
    osv: true,
    kics: true,
    trivy: true,
    zap: false, // disabled by default unless a target is supplied
    noir: true,
  }

  // Merge with provided enables
  const enabled: Record<ToolKey, boolean> = Object.assign({}, enableDefault)
  for (const key of Object.keys(opts.enabled) as ToolKey[]) {
    const v = opts.enabled[key]
    if (typeof v === 'boolean') enabled[key] = v
  }
  if (!opts.zapTarget) enabled.zap = false

  const results: RunResult[] = []

  // 1. Semgrep
  if (enabled.semgrep) {
    logHeader(TOOL_LABELS.semgrep)
    results.push(await runSemgrep(outDir))
  } else {
    console.log('Semgrep disabled.')
  }

  // 2. CodeQL
  if (enabled.codeql) {
    logHeader(TOOL_LABELS.codeql)
    results.push(await runCodeQL(outDir))
  } else {
    console.log('CodeQL disabled.')
  }

  // 3. Gitleaks
  if (enabled.gitleaks) {
    logHeader(TOOL_LABELS.gitleaks)
    results.push(await runGitleaks(outDir))
  } else {
    console.log('Gitleaks disabled.')
  }

  // 4. Syft (SBOM)
  let sbomPath = join(outDir, 'sbom.cdx.json')
  if (enabled.syft) {
    logHeader(TOOL_LABELS.syft)
    const r = await runSyft(outDir)
    results.push(r)
    sbomPath = r.output || sbomPath
  } else {
    console.log('Syft disabled.')
  }

  // 5. osv-scanner (consumes SBOM)
  if (enabled.osv) {
    logHeader(TOOL_LABELS.osv)
    results.push(await runOSV(outDir, sbomPath))
  } else {
    console.log('osv-scanner disabled.')
  }

  // 6. KICS
  if (enabled.kics) {
    logHeader(TOOL_LABELS.kics)
    results.push(await runKICS(outDir))
  } else {
    console.log('KICS disabled.')
  }

  // 7. Trivy
  if (enabled.trivy) {
    logHeader(TOOL_LABELS.trivy)
    results.push(await runTrivy(outDir))
  } else {
    console.log('Trivy disabled.')
  }

  // 8. OWASP ZAP
  if (enabled.zap) {
    logHeader(TOOL_LABELS.zap)
    results.push(await runZAP(outDir, opts.zapTarget))
  } else {
    console.log(`OWASP ZAP disabled.${opts.zapTarget ? '' : ' No target provided.'}`)
  }

  // 9. Noir (+ generic conversion)
  if (enabled.noir) {
    logHeader(TOOL_LABELS.noir)
    results.push(await runNoir(outDir))
  } else {
    console.log('Noir disabled.')
  }

  // Summary
  logHeader('Summary')
  const pad = (s: string, n: number) => (s + ' '.repeat(n)).slice(0, n)
  for (const r of results) {
    const name = pad(TOOL_LABELS[r.tool], 12)
    const status = r.ok ? 'OK' : 'WARN'
    console.log(`${name}  ${status}  -> ${r.output || '-'}${r.error ? ` (${r.error})` : ''}`)
  }
  console.log(`\nReports directory: ${outDir}`)
  console.log('Report generation complete.')
}

main().catch((e) => {
  console.error('Security scan failed with error:', e)
  process.exit(1)
})
