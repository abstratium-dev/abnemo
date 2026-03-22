---
trigger: manual
---

In the current regulatory landscape of 2026, managing a Software Bill of Materials (SBOM) for an open-source project is no longer just a "best practice"—it is becoming a legal and operational requirement, especially for entities based in Switzerland (like your Sàrl) that distribute code globally.

While the MIT or similar Licenses itself is permissive, the EU Cyber Resilience Act (CRA) and the revised Swiss Federal Act on Data Protection (nFADP) create new obligations for how you document and report what is "under the hood" of your software.

# 1. Regulatory Drivers for Your Project

As a Swiss Sàrl, you sit at a unique crossroads of Swiss and EU law.

## The EU Cyber Resilience Act (CRA)

Even though you are in Vaud, the CRA has extraterritorial effect. If your software is used by EU companies or "placed on the EU market" as part of a commercial activity, the CRA applies.

## Commercial vs. Non-Commercial

Purely hobbyist open-source is exempt. However, because you are an Sàrl (a commercial entity), the EU may view your project as part of a "commercial activity" if you provide paid support, accept significant corporate donations, or use the project to promote a commercial product.

## The SBOM Requirement

Under the CRA, manufacturers must maintain an SBOM to identify and document vulnerabilities. From September 2026, mandatory reporting of exploited vulnerabilities begins.

The Revised Swiss Data Protection Act (nFADP)
While the nFADP focuses on personal data, its "Privacy by Design" requirement (Art. 7) mirrors the CRA's "Security by Design." An SBOM is the primary tool to prove you are not using "high-risk" or end-of-life dependencies that could lead to a data breach.

# 2. The "Minimum Elements" of your SBOM

To be compliant with 2026 standards (specifically the updated NTIA and CISA guidelines), your SBOM should be a machine-readable file (e.g., sbom.json) containing these 7 core fields for every dependency:

|Field|Description|
|--------|------------------|
|Supplier Name|The creator of the component (e.g., "The Python Software Foundation").|
|Component Name|The name of the library or module.|
|Version|Specific version string used in your build.|
|Unique Identifier|A PURL (Package URL) or CPE (Common Platform Enumeration).|
|Dependency Relationship|How it connects to your code (e.g., "Primary" or "Transitive").|
|Author of SBOM|abstratium informatique Sàrl.|
|Timestamp|When the SBOM was last generated.|

Pro Tip: In 2026, it is also highly recommended to include Cryptographic Hashes (SHA-256) for each component to prevent "dependency confusion" attacks.

# 3. Implementation for GitHub Projects

Since your code is on GitHub, you don't need to write this manually. You should automate the generation to ensure it updates with every release.
Format: Use CycloneDX or SPDX. These are the industry standards recognized by both Swiss and EU authorities.

## Tooling

### GitHub Dependency Graph

GitHub can automatically generate an exportable SBOM for you (look under the "Insights" > "Dependency Graph" tab).

### GitHub Actions

Use actions like anchore/sbom-action to generate and attach an SBOM to your "Releases" page automatically.

### VEX (Vulnerability Exploitability eXchange)

If your SBOM shows a vulnerable library, but your code doesn't actually call the "broken" part of that library, you use a VEX statement to tell users: "Yes, we use this library, but we aren't affected."

# 4. implementation

Create a file at `.github/workflows/sbom.yml` in your repository.
here are the contents:

```
name: Continuous Compliance (SBOM & Scan)

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  compliance-and-sbom:
    runs-on: ubuntu-latest
    permissions:
      contents: write # Needed to push the SBOM back to the repo
      security-events: write # Needed for vulnerability reporting

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Generate CycloneDX SBOM
        uses: anchore/sbom-action@v0
        with:
          format: 'cyclonedx-json'
          output-file: 'sbom.json'

      # VULNERABILITY SCAN: Essential for CRA/nFADP compliance
      - name: Scan SBOM for Vulnerabilities
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'sbom'
          scan-ref: 'sbom.json'
          format: 'table'
          exit-code: '1' # This will fail the build if "Critical" bugs are found
          severity: 'CRITICAL,HIGH'

      # PUSH TO REPO: Makes it available for anyone who clones
      - name: Commit SBOM to Repository
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action"
          git add sbom.json
          git commit -m "docs: update auto-generated SBOM [skip ci]" || echo "No changes to commit"
          git push
```
