# Security policy

These servers take actions on real infrastructure, so security reports matter most here.

## Report a vulnerability

Please **don't open a public issue**. Report privately through GitHub:
[Security → Report a vulnerability](https://github.com/robertherbaugh/vigil-mcp-servers/security/advisories/new).

Include what you found, how to reproduce it, and what an attacker could do with it. You'll get an
acknowledgement within a few days. Fixes are released with a GitHub Security Advisory and credit,
unless you'd rather stay anonymous.

## In scope

- A way to make a server act outside its allow list, rate limit or TTL bounds
- A way to run a command or reach a URL the server's config doesn't name
- Authentication bypass, or a token or upstream credential leaking (logs, errors, tool output)
- A tool whose declared effect class understates what it does

## Supported versions

Only the latest commit on `main` until the first tagged release.
