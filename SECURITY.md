# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability within VulnScope, please send an email to [0mayankbasena@gmail.com](mailto:0mayankbasena@gmail.com). All security vulnerabilities will be promptly addressed.

**Please do NOT report security vulnerabilities through public GitHub issues.**

## Disclosure Policy

When the security team receives a security bug report, they will assign it to a primary handler. This person will coordinate the fix and release process, including the following:

1. Confirm the problem and determine the affected versions.
2. Audit code to find any potential similar problems.
3. Prepare fixes for all releases still under maintenance.
4. Release a new security fix version.

## Security Update Policy

Security updates will be released as soon as possible after a vulnerability is confirmed and a fix is ready. Users are encouraged to update to the latest version promptly.

## Security Related Configuration

- The API uses CORS middleware. In production, restrict `allow_origins` to specific domains instead of `["*"]`.
- Database credentials should be stored in environment variables, not hardcoded.
- API keys for NVD and Exploit-DB should be configured via environment variables.

## Known Security Gaps

- CORS is configured to allow all origins (`*`) in development mode. Tighten this for production deployments.
- The alert configuration endpoint does not validate webhook URLs. Ensure proper URL validation before deploying alerts.

## Contact

For any security concerns, contact:
- **Mayank Basena**: [0mayankbasena@gmail.com](mailto:0mayankbasena@gmail.com)
- **GitHub**: [mayank-dev-15](https://github.com/mayank-dev-15)
