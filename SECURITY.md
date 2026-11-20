# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report vulnerabilities privately through GitHub:
**Security → Report a vulnerability** on this repository
(private vulnerability reporting). Include affected version/commit, reproduction
steps and impact. We aim to acknowledge reports within 3 business days.

## Supported versions

Only the latest commit on `main` is supported.

## Security practices in this repo

- **Secret scanning with push protection**: pushes containing recognised secrets are blocked.
- **CodeQL code scanning** (`security-extended` queries) for Go, TypeScript and GitHub Actions on every push, PR and weekly.
- **Dependabot**: alerts, security updates and weekly version updates for Go, npm, GitHub Actions, Docker,
  Terraform and pip.
- **Dependency review** blocks PRs that introduce dependencies with high or critical vulnerabilities.

## Deployment hardening notes

- Never commit `.env`, `*.tfvars` or Terraform state; they're git-ignored and contain secrets. Use a remote
  Terraform backend for shared deployments.
- In Azure, the app is behind Entra ID (Easy Auth). `/taxii2/*` and `/mcp` use their own generated tokens
  (Key Vault), and the storage account has shared-key access disabled (managed identity only).
- The research agent and MCP tools are read-only. Article text is treated as untrusted input in all prompts.
