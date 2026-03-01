# Security Policy

## Reporting Security Vulnerabilities

We take the security of abstratium projects seriously and are deeply grateful to security researchers who help us keep our users safe. If you discover a security vulnerability, we would be incredibly thankful if you could disclose it to us in a responsible manner. Your efforts in finding and reporting security issues are invaluable to us and the community!

### How to Report a Security Vulnerability

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by email to:

**security@abstratium.dev**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

### What to Include in Your Report

To help us better understand and resolve the issue, please include as much of the following information as possible:

- **Type of vulnerability** (e.g., SQL injection, cross-site scripting, authentication bypass, etc.)
- **Full paths of source file(s)** related to the manifestation of the vulnerability
- **Location of the affected source code** (tag/branch/commit or direct URL)
- **Step-by-step instructions to reproduce the issue**
- **Proof-of-concept or exploit code** (if possible)
- **Impact of the vulnerability**, including how an attacker might exploit it
- **Any potential mitigations** you've identified

### What to Expect

After you submit a vulnerability report, we will:

1. **Acknowledge receipt** of your vulnerability report within 48 hours
2. **Confirm the vulnerability** and determine its severity
3. **Work on a fix** and keep you informed of our progress
4. **Release a security patch** as soon as possible
5. **Publicly acknowledge your responsible disclosure** with gratitude (if you wish to be credited)

### Disclosure Timeline

- **Day 0**: Vulnerability reported to security@abstratium.dev
- **Day 1-2**: Acknowledgment sent to reporter
- **Day 3-7**: Vulnerability confirmed and severity assessed
- **Day 7-30**: Fix developed and tested
- **Day 30-45**: Security patch released
- **Day 45+**: Public disclosure (coordinated with reporter)

We aim to release security patches within 30 days of confirmation. For critical vulnerabilities, we will expedite the process.

### Scope

This security policy applies to the following:

- This repository
- All versions currently marked as supported
- Security vulnerabilities in dependencies (we will coordinate with upstream projects)

### Out of Scope

The following are generally **not** considered security vulnerabilities:

- Vulnerabilities in outdated or unsupported versions
- Issues that require physical access to a user's device
- Social engineering attacks
- Denial of service attacks that require excessive resources
- Issues in third-party services or dependencies (report to the respective projects)
- Vulnerabilities requiring unlikely user interaction

### Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

### Security Best Practices

When deploying this project, please follow these security best practices:

1. **Use HTTPS** - Always deploy behind a reverse proxy with TLS/SSL
2. **Secure secrets** - Store all secrets (JWT keys, OAuth client secrets, pepper) in environment variables
3. **Regular updates** - Keep dependencies and the application up to date
4. **Strong passwords** - Enforce strong password policies for user accounts
5. **Rate limiting** - Enable and configure rate limiting for production
6. **Monitor logs** - Regularly review security logs for suspicious activity
7. **Database security** - Secure your database with strong credentials and network isolation

### Security Features

This project includes the following security features:

- **OAuth 2.0 with PKCE** - Prevents authorization code interception
- **CSRF protection** - State parameter validation
- **CORS** - Prevents cross-origin requests from unauthorized domains
- **Content Security Policy** - Prevents XSS and code injection
- **Security headers** - HSTS, X-Frame-Options, etc.

### Recognition and Gratitude

While we currently do not have a formal bug bounty program, we are extremely grateful to security researchers who help protect our users. We will:

- **Publicly acknowledge your contribution** in our release notes and security advisories (with your permission)
- **Credit you in our Hall of Fame** (coming soon) for responsible disclosure
- **Send you our heartfelt thanks** for making the internet a safer place
- **Consider implementing a bug bounty program** in the future as the project grows

Your time and expertise in finding and reporting vulnerabilities is a gift to the open source community, and we truly appreciate it!

### Safe Harbor and Legal Protection

We are committed to working with security researchers and will not pursue legal action against anyone who:

- Makes a good faith effort to avoid privacy violations, data destruction, and service interruption
- Only interacts with accounts they own or with explicit permission from the account holder
- Does not exploit the vulnerability beyond what is necessary to demonstrate it
- Reports the vulnerability promptly
- Keeps the vulnerability confidential until we've had a chance to address it

We believe in fostering a positive relationship with the security research community and welcome your contributions!

### Contact

We'd love to hear from you! For security-related questions or concerns, contact:

**Email**: security@abstratium.dev

For general questions, please use the regular issue tracker.

**Thank you for helping us build a more secure application!** 🙏

### References

This security policy follows industry best practices:

- [GitHub Security Policy Guidelines](https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository)
- [OWASP Vulnerability Disclosure Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)
- [ISO/IEC 29147:2018 - Vulnerability Disclosure](https://www.iso.org/standard/72311.html)

---

**Last Updated**: December 2025