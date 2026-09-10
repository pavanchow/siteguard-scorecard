# SiteGuard Scorecard

A comprehensive website security scanning tool built with modern web technologies.
Enter a URL and get a graded (A-F) security scorecard covering headers, cookies,
exposed files, TLS, mixed content, and subdomain-takeover risk.

## Status

- Frontend (Astro + React): builds clean, deploys to GitHub Pages via GitHub Actions.
  Live URL: https://pavanchow.github.io/siteguard-scorecard/
- Scanner (Cloudflare Worker): builds clean, 17 passing `vitest` tests, verified
  end-to-end against live sites with `wrangler dev`. Not yet deployed to Cloudflare
  (needs a Cloudflare account/API token, see Deployment below).
- Because the Worker is not deployed yet, the hosted frontend defaults its API base
  to `http://localhost:8787`. Run the Worker locally, or set `PUBLIC_WORKER_URL`
  (see Configuration) to point the hosted UI at a deployed Worker.

## Features

- **Security Headers Analysis**: Checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **Cookie Security Audit**: Validates Secure, HttpOnly, and SameSite flags
- **Exposed Files Detection**: Scans for .git, .env, package.json, wp-config.php
- **TLS Configuration Check**: Verifies modern TLS usage
- **Mixed Content Detection**: Finds insecure HTTP resources on HTTPS pages
- **Subdomain Takeover Risk**: Identifies dangling CNAME records pointing to vulnerable providers

## Tech Stack

- **Frontend**: Astro, React, TailwindCSS, TypeScript
- **Backend**: Cloudflare Workers, Hono framework, TypeScript
- **CI/CD**: GitHub Actions

## Repository Structure

```
/
├── frontend/           # Astro frontend application
│   ├── src/
│   │   ├── pages/     # Astro pages
│   │   ├── components/# React components
│   │   ├── scripts/   # Client-side JavaScript
│   │   ├── styles/    # TailwindCSS styles
│   │   └── types/     # TypeScript type definitions
│   └── package.json
├── scanner/            # Cloudflare Worker backend
│   ├── src/
│   │   ├── index.ts   # Hono app entry point
│   │   └── scanner.ts # Security scanning logic
│   ├── package.json
│   └── wrangler.toml
├── .github/
│   └── workflows/
│       └── deploy.yml # CI/CD pipeline
└── package.json       # Root workspace config
```

## Getting Started

### Prerequisites

- Node.js 20+
- npm or pnpm
- Cloudflare account (for deploying the scanner)
- GitHub account (for CI/CD)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/pavanchow/v1.git
cd v1
```

2. Install dependencies:
```bash
npm install
```

3. Install frontend dependencies:
```bash
cd frontend && npm install
```

4. Install scanner dependencies:
```bash
cd ../scanner && npm install
```

### Local Development

**Run Scanner (Cloudflare Worker) first:**
```bash
cd scanner
npm run dev          # wrangler dev, serves at http://localhost:8787
```

**Run Frontend:**
```bash
cd frontend
npm run dev          # astro dev, serves at http://localhost:4321/v1/
```
The frontend defaults to calling the Worker at `http://localhost:8787`, so with
both running you can scan a site end to end from the browser.

### Testing

```bash
cd scanner
npm test             # vitest run - 17 unit tests for the core checks + grading
npm run typecheck    # tsc --noEmit
```

### Configuration

The frontend reads the Worker API base URL from the `PUBLIC_WORKER_URL` build-time
environment variable (Astro `PUBLIC_` convention), defaulting to
`http://localhost:8787`.

- Local build against a custom Worker:
  ```bash
  cd frontend
  PUBLIC_WORKER_URL="https://your-worker.workers.dev" npm run build
  ```
- In CI (GitHub Actions), set a repository **variable** named `PUBLIC_WORKER_URL`
  (Settings -> Secrets and variables -> Actions -> Variables). The deploy workflow
  passes it into the build automatically.

The GitHub Pages base path is configured as `/v1` in `frontend/astro.config.mjs`
(`site`/`base`) to match the project page `https://pavanchow.github.io/v1/`.

### Deployment

#### Frontend -> GitHub Pages (automated, live)

Pages is enabled with the "GitHub Actions" build source. Every push to `main`
runs `.github/workflows/deploy.yml`, which builds the Astro site and publishes it
to `https://pavanchow.github.io/v1/`. No secrets required.

#### Scanner -> Cloudflare Workers (needs a Cloudflare account)

The Worker is fully runnable locally but not yet deployed, because deploying
requires Cloudflare credentials. To deploy it:

```bash
cd scanner
npx wrangler login          # interactive, OR export CLOUDFLARE_API_TOKEN
npm run deploy              # wrangler deploy
```

For CI deployment, add a repository **secret** `CLOUDFLARE_API_TOKEN` (a Cloudflare
API token with the "Edit Cloudflare Workers" permission). The `deploy-scanner` job
in the workflow runs the tests on every push and deploys the Worker only when that
secret is present, so the pipeline stays green without it.

After deploying the Worker, set the `PUBLIC_WORKER_URL` repo variable to the
Worker's URL and re-run the frontend deploy so the hosted UI targets it.

## API Reference

### POST /scan

Scan a website for security vulnerabilities.

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "overallScore": 85,
  "grade": "B",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "checks": {
    "securityHeaders": {
      "status": "warning",
      "score": 75,
      "findings": [...],
      "remediation": "..."
    },
    "cookieFlags": {...},
    "exposedFiles": {...},
    "tlsGrade": {...},
    "mixedContent": {...},
    "subdomainTakeover": {...}
  }
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

## Grading System

| Grade | Score Range | Description |
|-------|-------------|-------------|
| A     | 90-100      | Excellent security posture |
| B     | 80-89       | Good security, minor improvements needed |
| C     | 70-79       | Average security, several issues to address |
| D     | 60-69       | Below average, significant vulnerabilities |
| F     | 0-59        | Critical security issues present |

## Security Checks Explained

### Security Headers
Evaluates presence of critical HTTP security headers that protect against common web vulnerabilities.

### Cookie Flags
Ensures cookies are configured with appropriate security flags to prevent theft and misuse.

### Exposed Files
Detects accidentally exposed sensitive files that could leak credentials or source code.

### TLS Configuration
Verifies the website uses modern encryption protocols.

### Mixed Content
Identifies insecure HTTP resources loaded on HTTPS pages.

### Subdomain Takeover
Checks for CNAME records pointing to services that may have been abandoned.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning websites you do not own.
