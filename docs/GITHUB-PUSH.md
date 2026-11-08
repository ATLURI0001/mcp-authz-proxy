# Push your repository

Extract the ZIP, open the `mcp-authz-proxy` folder in VS Code, and open a terminal.
Create an **empty** GitHub repository named `mcp-authz-proxy` under `ATLURI0001`.
Do not initialize that remote with a README or license; both are already included.

Run these commands in PowerShell, Git Bash, or a Linux/macOS terminal:

```bash
git init
git add .
git status
git commit -m "Build scoped authorization gateway for MCP tools"
git branch -M main
git remote add origin https://github.com/ATLURI0001/mcp-authz-proxy.git
git push -u origin main
```

Review `git status` before committing: `.env`, binaries and logs are ignored. Do
not force-push over an existing repository. These instructions assume an empty
remote; if you already created one with files, reconcile its history first.

Description:
> Go-based MCP authorization gateway with scoped tool access, per-user credentials, single-use approvals, and auditable execution.

Suggested topics:
`go`, `golang`, `mcp`, `model-context-protocol`, `authorization`, `oauth2`, `security`,
`api-gateway`, `devops`, `postgresql`, `redis`, `prometheus`, `grafana`, `docker`

After CI passes, tag a version to build downloadable binaries:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow uploads six OS/architecture bundles as GitHub Actions
artifacts. It does not automatically create a public GitHub Release or publish a
container image. Use the artifacts to create a release after reviewing the build.
No GitHub repository has been created or pushed on your behalf.
