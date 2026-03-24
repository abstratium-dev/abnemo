# SBOM & Compliance Documentation

## Overview

This project maintains a Software Bill of Materials (SBOM) to comply with:
- **EU Cyber Resilience Act (CRA)** - Effective 2026
- **Swiss Federal Act on Data Protection (nFADP)** - Art. 7 (Privacy by Design)

As a Swiss Sàrl distributing software globally, maintaining an SBOM is both a legal requirement and a security best practice.

## SBOM Generation

The SBOM is automatically generated using the **CycloneDX** format, which is recognized by both Swiss and EU regulatory authorities.

### Automation

The SBOM is generated automatically via GitHub Actions on every push to the `main` branch. The workflow:

1. **Generates** a CycloneDX JSON SBOM (`sbom.json`)
2. **Scans** for vulnerabilities using Trivy
3. **Commits** the SBOM back to the repository
4. **Fails** the build if CRITICAL or HIGH severity vulnerabilities are detected

### Manual Generation

To manually trigger SBOM generation:
1. Go to the "Actions" tab in GitHub
2. Select "Continuous Compliance (SBOM & Scan)"
3. Click "Run workflow"

## SBOM Contents

The generated `sbom.json` includes the following for each dependency:

| Field | Description |
|-------|-------------|
| **Supplier Name** | The creator of the component |
| **Component Name** | Library or module name |
| **Version** | Specific version used |
| **Unique Identifier** | PURL (Package URL) or CPE |
| **Dependency Relationship** | Primary or transitive dependency |
| **Author of SBOM** | abstratium informatique Sàrl |
| **Timestamp** | Generation date/time |
| **Cryptographic Hash** | SHA-256 for integrity verification |

## Vulnerability Management

### Scanning

Vulnerabilities are automatically scanned using **Trivy** on every SBOM generation. The scan:
- Checks against the latest CVE databases
- Reports CRITICAL and HIGH severity issues
- Fails the build if critical vulnerabilities are found

### VEX Statements

If a vulnerability is reported but doesn't affect your code (e.g., you don't use the vulnerable function), you can create a VEX (Vulnerability Exploitability eXchange) statement to document this.

## Compliance Timeline

- **September 2026**: Mandatory reporting of exploited vulnerabilities begins (CRA)
- **Ongoing**: SBOM must be updated with each release

## Accessing the SBOM

The current SBOM is available at the root of the repository as `sbom.json`. It is automatically updated with each push to `main`.

### For Users

If you're using this software in a regulated environment:
1. Download `sbom.json` from the repository
2. Import it into your compliance management system
3. Check for any vulnerabilities that may affect your deployment

### For Auditors

The SBOM provides full transparency of all dependencies, their versions, and known vulnerabilities. The automated scanning ensures continuous compliance monitoring.

## Dependencies

### Production Dependencies
- scapy >= 2.5.0
- dnspython >= 2.4.0
- tabulate >= 0.9.0
- flask >= 2.3.0
- flask-wtf >= 1.1.0
- watchdog >= 3.0.0
- cryptography >= 41.0.0

### Development Dependencies
See `requirements-dev.txt` for the complete list of testing and code quality tools.

## Contact

For compliance-related questions:
**abstratium informatique Sàrl**

## References

- [EU Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)
- [Swiss nFADP](https://www.fedlex.admin.ch/eli/cc/2022/491/en)
- [CycloneDX Specification](https://cyclonedx.org/)
- [NTIA SBOM Guidelines](https://www.ntia.gov/page/software-bill-materials)
