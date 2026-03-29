# Development Guide

## Developing and Testing

See [DESIGN.md](DESIGN.md) for information about the design of this application.
Tests consist of normal Python tests and Playwright end-to-end tests. Instructions on running them are in the main [README.md](../README.md) file.

## Release Process

### 1. Run Unit Tests Locally

Run the full test suite with coverage:

```bash
# Run all tests with verbose output and coverage
source /w/abstratium-abnemo.env
sudo python3 -m pytest -v --cov=. --cov-report=term-missing

# Ensure all tests pass before proceeding
# Ensure coverage is as required (see [testing.md](../.windsurf/rules/testing.md))
```

### 2. Run E2E Tests Locally

Run the Playwright end-to-end tests:

```bash
# Navigate to e2e tests directory
cd e2e-tests

# Source the environment file
source /w/abstratium-abnemo.env

# ensure browsers are installed
sudo npx playwright install

# Run the tests with the server auto-starting
sudo BASE_URL=http://localhost:40002 npx playwright test
```

Alternatively, don't set `BASE_URL` and start the server using the `start-e2e-server.sh` script and then use the Playwright UI with `npx playwright test --ui`.

### 3. Commit changes

If you have any final changes to commit:

```bash
git status

# Stage all changes
git add .

# Commit with a descriptive message
git commit -m "chore: prepare for release vX.Y.Z"

# Push to main branch
git push origin main
```

### 4. Wait for SBOM Generation

After pushing to `main`, the GitHub Actions workflow will automatically:

1. Generate a new SBOM (Software Bill of Materials) in CycloneDX format
2. Scan for vulnerabilities (CRITICAL and HIGH severity)
3. Commit the updated `sbom.json` file back to the repository

**Important:** Wait for this workflow to complete before creating the release. You can monitor it at:
```
https://github.com/abstratium-dev/abnemo/actions/workflows/sbom.yml
```

The workflow typically takes 1-2 minutes to complete. Look for the commit message:
```
docs: update auto-generated SBOM [skip ci]
```

### 5. Pull the SBOM Commit

Once the SBOM workflow completes, pull the new commit:

```bash
git pull origin main
```

You should see the updated `sbom.json` file in your local repository.

### 6. Create a Git Tag

Create an annotated tag for the release:

```bash
# Create annotated tag (replace vX.Y.Z with your version)
git tag -a v1.0.0 -m "Release v1.0.0"

# Push the tag to GitHub
git push origin v1.0.0
```

**Version numbering:**
- **Major (X):** Breaking changes or major new features
- **Minor (Y):** New features, backward compatible
- **Patch (Z):** Bug fixes, backward compatible

### 7. Create GitHub Release

1. Go to the GitHub repository: https://github.com/abstratium-dev/abnemo
2. Click on "Releases" in the right sidebar
3. Click "Draft a new release"
4. Fill in the release form:
   - **Tag:** Select the tag you just created (e.g., `v1.0.0`)
   - **Release title:** Same as tag (e.g., `v1.0.0`)
   - **Description:** Add release notes describing:
     - New features
     - Bug fixes
     - Breaking changes (if any)
     - Known issues (if any)
5. Click "Publish release"

### 8. Verify Release

After publishing:

1. Verify the release appears on the releases page
2. Verify the `sbom.json` file is included in the release assets
3. Download and test the release tarball (optional but recommended)

## Release Notes Template

Use this template for your release description:

```markdown
## What's New

- Feature 1: Description
- Feature 2: Description

## Bug Fixes

- Fix 1: Description
- Fix 2: Description

## Breaking Changes

- Change 1: Description and migration instructions

## Compliance

This release includes:
- ✅ CycloneDX SBOM (sbom.json)
- ✅ Vulnerability scan (CRITICAL and HIGH severity)

## Installation

See [README.md](https://github.com/abstratium-dev/abnemo/blob/main/README.md) for installation instructions.
```

## Troubleshooting

### Tag Already Exists

If you need to recreate a tag:

```bash
# Delete local tag
git tag -d v1.0.0

# Delete remote tag
git push origin :refs/tags/v1.0.0

# Create new tag
git tag -a v1.0.0 -m "Release v1.0.0"

# Push new tag
git push origin v1.0.0
```

