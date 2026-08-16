# SiteGuard Scorecard

A comprehensive website security scanning tool built with modern web technologies.

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
git clone <repository-url>
cd siteguard-scorecard
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

**Run Frontend:**
```bash
cd frontend
npm run dev
```
The frontend will be available at `http://localhost:4321`

**Run Scanner (Cloudflare Worker):**
```bash
cd scanner
npm run dev
```
The scanner API will be available at `http://localhost:8787`

### Configuration

Update the worker URL in the frontend if deploying to production:

1. In `frontend/src/pages/index.astro`, update the default `workerUrl` prop
2. Or set `window.WORKER_URL` before the app loads

### Deployment

#### Manual Deployment

**Deploy Frontend to GitHub Pages:**
```bash
cd frontend
npm run build
# Deploy the dist folder to gh-pages branch
```

**Deploy Scanner to Cloudflare:**
```bash
cd scanner
# Login to Cloudflare
npx wrangler login
# Deploy
npm run deploy
```

#### Automated Deployment (CI/CD)

The GitHub Actions workflow automatically deploys both components when you push to `main`:

1. Go to your GitHub repository settings
2. Add the following secrets:
   - `CLOUDFLARE_API_TOKEN`: Your Cloudflare API token with Workers permissions

3. Push to main branch to trigger deployment

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
