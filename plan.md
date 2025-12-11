- DefectDojo setup and access
  - Deploy a reachable, secured DefectDojo instance, provision an API v2 key, and define the target Product and Engagement to receive findings.
  - Centralize configuration (DD URL, API key, product_name, engagement_name) and ensure it is securely stored and easily selectable per pipeline run.

- Security scanning pipeline stage (“security_scan”)
  - Execute nine distinct security tools as dedicated steps covering: source code analysis (Semgrep, CodeQL), secrets detection (Gitleaks, Trivy), SBOM generation (Syft) and dependency scanning via SBOM (osv-scanner), IaC misconfiguration (KICS, Trivy), container/dependency vulnerabilities (Trivy), DAST against the deployed endpoint (OWASP ZAP), and Noir analysis.
  - For each tool, enforce the intended scan scope (e.g., exclude non-code for Semgrep, scan full history for Gitleaks, osv-scanner consumes the Syft SBOM, Trivy multi-scan for vulnerabilities/secrets/IaC) and produce outputs in formats compatible with DefectDojo’s parsers.
  - Normalize Noir results into a Generic Findings JSON suitable for DefectDojo’s generic import.

- Consolidation and upload to DefectDojo
  - Aggregate all tool outputs and upload them to DefectDojo using the reimport flow to enable continuous deduplication.
  - Accurately map each upload to the configured Product and Engagement, specifying the correct scan type per tool.
  - Provide resilient error handling and logging for upload failures so pipeline completion is not blocked by DefectDojo connectivity issues.

- Validation and deduplication outcomes
  - Verify post-run that DefectDojo shows 10 separate Tests under the target Engagement, one per tool/report.
  - Confirm deduplication behavior: overlapping vulnerabilities from multiple tools result in a single Active Finding with duplicates marked accordingly.
  - Produce a post-run summary (counts per tool, upload status) to assist manual verification in the DefectDojo UI.

- Configurability and observability
  - Allow configuration of the target application endpoint for OWASP ZAP, and toggles to enable/disable specific tools as needed.
  - Retain generated reports as pipeline artifacts and present a concise run-level summary (findings counts, dedup status indicators, and any upload warnings) for transparency and auditing.
