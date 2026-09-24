# SafeLink: SAST Auditing with Bearer CLI and Azure Deployment

Functional web application and REST API built for **Group Activity 1** (Software Quality and Testing).

## Core Features

1. **Web Application and REST API (`src/`)**: A Node.js and Express URL shortener hardened with `helmet` security headers, strict protocol validation (`http:` and `https:`) against open redirects (`CWE-601`), and SHA-256 IP address hashing to prevent sensitive data leaks (`CWE-532`).
2. **SAST and Data Flow Scanner (`Bearer CLI`)**: Integrated into `.github/workflows/ci-cd.yml` as an open-source analyzer listed under **OWASP Source Code Analysis Tools**, scanning for OWASP Top 10 vulnerabilities and sensitive data flows.
3. **Automated Cloud Deployment**: Multi-stage Docker build pushed to GitHub Container Registry (`ghcr.io`) and deployed automatically to **Azure App Service** (`https://upt-awa-577.azurewebsites.net`).

## Local Execution

```bash
npm install
npm test
npm start
```

The server starts at `http://localhost:8080`.
