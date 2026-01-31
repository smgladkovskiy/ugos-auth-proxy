# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability within UGOS Auth Proxy, please send an email to smgladkovskiy@gmail.com.

**Please do not report security vulnerabilities through public GitHub issues.**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we
received your original message.

Please include the following information:

- Type of issue (e.g., buffer overflow, authentication bypass, etc.)
- Full paths of source file(s) related to the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue

## Security Considerations

This service:

1. **Requires root access** to read `/etc/shadow` - ensure proper access controls
2. **Should not be exposed externally** - use internal Docker networks only
3. **Does not store passwords** - validates against system shadow file in real-time
4. **Logs authentication attempts** - monitor for suspicious activity

## Best Practices

- Mount `/etc/shadow` as read-only
- Use HTTPS between authentik and this proxy (via reverse proxy)
- Implement rate limiting at the network level
- Monitor authentication logs for brute-force attempts
