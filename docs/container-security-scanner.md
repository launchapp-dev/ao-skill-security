# Container Security Scanner Documentation

## Overview

The Container Security Scanner is a static analysis tool that scans Dockerfiles, docker-compose files, and container configurations to identify security vulnerabilities and misconfigurations before deployment. It detects dangerous patterns that could lead to privilege escalation, data exposure, or container compromise.

## Installation

The container security scanner is included in the `ao.security` skill pack. To use it:

```bash
# Install the skill pack
ao skill install ao.security

# Run container security scan
ao workflow run ao.security/container-scan
```

## Quick Start

### Basic Scan

```bash
# Scan current directory for container security issues
ao workflow run ao.security/container-scan

# Scan specific directory
ao workflow run ao.security/container-scan --input '{"path": "docker"}'

# Output as JSON
ao workflow run ao.security/container-scan --output json > container-report.json
```

### Scan and Fix

```bash
# Scan for vulnerabilities and automatically create fix tasks
ao workflow run ao.security/container-scan-and-fix
```

## How It Works

### 1. File Discovery

The scanner finds all container-related files:

- `Dockerfile`, `Dockerfile.dev`, `Dockerfile.prod`
- `docker-compose.yml`, `docker-compose.yaml`
- `docker-compose.*.yml` (environment-specific)
- `Containerfile`, `Containerfile.*`

### 2. Dockerfile Analysis

Parses Dockerfile instructions to detect:

- **FROM**: Base image security, EOL versions, :latest tags
- **USER**: Missing or root user execution
- **HEALTHCHECK**: Missing or improperly configured
- **RUN/COPY/ADD**: Privilege escalation patterns
- **VOLUME**: Sensitive mount points

### 3. Docker Compose Analysis

Parses service definitions to detect:

- **volumes**: Sensitive host path mounts
- **network_mode**: Host network exposure
- **ports**: Dangerous port exposures
- **privileged**: Privilege escalation
- **cap_add/cap_drop**: Capability misconfigurations
- **deploy.resources**: Missing resource limits

### 4. Severity Classification

| Severity | Criteria | Example |
|----------|----------|---------|
| **CRITICAL** | Direct host escape vector | Docker socket mount, --privileged |
| **HIGH** | Significant privilege or data exposure | Root user, sensitive volumes |
| **MEDIUM** | Security hygiene issue | Missing HEALTHCHECK, :latest tag |
| **LOW** | Best practice violation | Missing labels, inefficient caching |
| **INFO** | Optimization suggestion | Multi-stage build opportunities |

## Detection Capabilities

### 1. Docker Socket Exposure

Detects containers with access to the Docker daemon:

```yaml
# ❌ DETECTED - CRITICAL
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

Impact: Container can escape and control host Docker daemon.

Remediation: Remove the Docker socket volume mount entirely.

### 2. Running as Root

Detects containers without proper user configuration:

```dockerfile
# ❌ DETECTED - HIGH
FROM node:18-alpine
WORKDIR /app
COPY . .
CMD ["node", "index.js"]
```

Impact: Container process has root privileges.

Remediation:
```dockerfile
# ✅ SAFE
FROM node:18-alpine
RUN addgroup -g 1001 -S nodejs && adduser -S nextjs -u 1001
WORKDIR /app
COPY --chown=nextjs:nodejs . .
USER nextjs
CMD ["node", "index.js"]
```

### 3. Missing HEALTHCHECK

Detects containers without health monitoring:

```dockerfile
# ❌ DETECTED - HIGH
FROM node:18-alpine
WORKDIR /app
COPY . .
CMD ["node", "index.js"]
```

Impact: Orchestrator cannot detect hung or crashed containers.

Remediation:
```dockerfile
# ✅ SAFE
FROM node:18-alpine
WORKDIR /app
COPY . .
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"
CMD ["node", "index.js"]
```

### 4. Use of :latest Tag

Detects unpredictable base image versions:

```dockerfile
# ❌ DETECTED - MEDIUM
FROM node:latest
FROM python:latest
```

Impact: Non-reproducible builds, potential breaking changes.

Remediation:
```dockerfile
# ✅ SAFE
FROM node:18-alpine
FROM python:3.11-slim
```

### 5. Sensitive Volume Mounts

Detects containers mounting sensitive host paths:

```yaml
# ❌ DETECTED - CRITICAL/HIGH
services:
  app:
    volumes:
      - /etc:/etc/readonly
      - /root:/root
      - /var/run/docker.sock:/var/run/docker.sock
```

Impact: Potential container escape and host compromise.

Remediation:
```yaml
# ✅ SAFE
services:
  app:
    volumes:
      - ./data:/app/data
```

### 6. Insecure Base Images

Detects EOL and untrusted base images:

```dockerfile
# ❌ DETECTED - HIGH
FROM python:2.7              # EOL
FROM ubuntu:14.04            # EOL
FROM node:8                  # EOL
FROM untrusted/image:latest  # Unknown registry
```

Impact: Known CVEs, unpatched vulnerabilities.

Remediation:
```dockerfile
# ✅ SAFE
FROM node:18-alpine
FROM python:3.11-slim
FROM ubuntu:22.04
```

### 7. Missing Resource Limits

Detects containers without resource constraints:

```yaml
# ❌ DETECTED - MEDIUM
services:
  app:
    image: myapp
    # No deploy.resources
```

Impact: Resource exhaustion attacks, noisy neighbor issues.

Remediation:
```yaml
# ✅ SAFE
services:
  app:
    image: myapp
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
```

### 8. Privilege Escalation Patterns

Detects containers with excessive privileges:

```bash
# ❌ DETECTED - CRITICAL
docker run --privileged myapp
docker run --network=host myapp
docker run --pid=host myapp
```

Impact: Full host compromise possible.

Remediation:
```bash
# ✅ SAFE
docker run --cap-drop=all --security-opt=no-new-privileges myapp
```

## Output Format

### JSON Report

```json
{
  "findings": [
    {
      "id": "CONT-001",
      "severity": "CRITICAL",
      "title": "Docker Socket Exposed to Container",
      "description": "Container has access to host Docker socket via volume mount",
      "file": "docker-compose.yml",
      "line": 15,
      "snippet": "  - /var/run/docker.sock:/var/run/docker.sock",
      "rule": "no-docker-socket",
      "cwe": "CWE-284",
      "owasp": "A01:2021 - Broken Access Control",
      "remediation": "Remove the Docker socket volume mount. If Docker-in-Docker is required, use a dedicated sidecar pattern with proper isolation.",
      "references": [
        "https://docs.docker.com/engine/security/security/",
        "https://www.twistlock.com/blog/attacking-docker-container-via-the-docker-socket/"
      ]
    }
  ],
  "summary": {
    "total": 8,
    "critical": 2,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
  },
  "scanned_files": 5,
  "scan_duration_ms": 1250
}
```

### Console Output

```
Container Security Scan Results
===============================

Scanned 5 files in 1.25s

Findings by Severity:
  🔴 CRITICAL: 2
  🟠 HIGH:     3
  🟡 MEDIUM:   2
  🟢 LOW:      1
  ℹ️  INFO:     0

CRITICAL Findings:
──────────────────

[CONT-001] Docker Socket Exposed to Container
  File: docker-compose.yml:15
  Code:   - /var/run/docker.sock:/var/run/docker.sock
  
  Impact: Container can escape and control host Docker daemon
  
  Remediation:
    Remove the Docker socket volume mount entirely.
    If Docker-in-Docker is required, use a dedicated sidecar pattern.
  
  References:
    • https://docs.docker.com/engine/security/security/
    • https://www.twistlock.com/blog/attacking-docker-container-via-the-docker-socket/
```

## Configuration

Create a `.ao/security.yaml` file to customize scanning:

```yaml
container_scanner:
  enabled: true
  
  # Scan scope
  scan_patterns:
    - "**/Dockerfile*"
    - "**/docker-compose*.yml"
    - "**/docker-compose*.yaml"
    - "**/Containerfile*"
  
  exclude_patterns:
    - "**/node_modules/**"
    - "**/.git/**"
  
  # Fail CI on these severities
  fail_on:
    - critical
    - high
  
  # Detection settings
  check_base_images: true
  check_user_instructions: true
  check_health_checks: true
  check_volume_mounts: true
  check_network_exposure: true
  check_resource_limits: true
  
  # Sensitive paths to flag
  sensitive_paths:
    - "/var/run/docker.sock"
    - "/etc"
    - "/root"
    - "/home"
    - "/var/run/secrets"
  
  # Trusted registries
  trusted_registries:
    - "docker.io"
    - "ghcr.io"
    - "registry.access.redhat.com"
  
  # Base image recommendations
  base_image_alternatives:
    "node:latest": "node:18-alpine"
    "python:latest": "python:3.11-slim"
    "ubuntu:latest": "ubuntu:22.04"
```

## Integration

### Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Run container security scan on staged files
ao workflow run ao.security/container-scan --staged

# Check exit code
if [ $? -ne 0 ]; then
  echo "Container security issues detected. Please fix before committing."
  exit 1
fi
```

### GitHub Actions

```yaml
name: Container Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup AO
        run: |
          curl -fsSL https://get.ao.dev | sh
          
      - name: Run Container Security Scan
        run: |
          ao workflow run ao.security/container-scan --output json > container-report.json
          
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: container-security-report
          path: container-report.json
          
      - name: Check for Critical Issues
        run: |
          CRITICALS=$(jq '.summary.critical' container-report.json)
          if [ "$CRITICALS" -gt 0 ]; then
            echo "Found $CRITICALS critical container security issues!"
            exit 1
          fi
```

### GitLab CI

```yaml
container-security-scan:
  stage: security
  script:
    - ao workflow run ao.security/container-scan --output json > container-report.json
  artifacts:
    reports:
      sast: container-report.json
    expire_in: 1 week
  rules:
    - if: $CI_MERGE_REQUEST_IID
    - if: $CI_COMMIT_BRANCH == "main"
```

## Remediation Guide

### 1. Create Non-Root User

**Before:**
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY . .
CMD ["node", "index.js"]
```

**After:**
```dockerfile
FROM node:18-alpine
RUN addgroup -g 1001 -S nodejs && adduser -S appuser -u 1001
WORKDIR /app
COPY --chown=appuser:nodejs package*.json ./
RUN npm ci --only=production && mv node_modules ./
COPY --chown=appuser:nodejs . .
USER appuser
CMD ["node", "index.js"]
```

### 2. Add Health Check

**Before:**
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY . .
CMD ["node", "index.js"]
```

**After:**
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY . .
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"
CMD ["node", "index.js"]
```

### 3. Pin Base Image Version

**Before:**
```dockerfile
FROM node:latest
FROM python:latest
```

**After:**
```dockerfile
FROM node:18-alpine@sha256:abc123...
FROM python:3.11-slim
```

### 4. Set Resource Limits

```yaml
services:
  app:
    image: myapp
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 128M
```

### 5. Remove Sensitive Volumes

**Before:**
```yaml
services:
  app:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/etc/readonly
```

**After:**
```yaml
services:
  app:
    volumes:
      - ./app-data:/app/data
```

### 6. Drop All Capabilities

```yaml
services:
  app:
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
```

## Best Practices

1. **Never Run as Root**: Always specify a USER instruction with a non-root user
2. **Pin Base Image Tags**: Use specific versions, never `:latest`
3. **Use Minimal Base Images**: Prefer alpine, slim, or distroless variants
4. **Add HEALTHCHECK**: Enable orchestrator to detect unhealthy containers
5. **Set Resource Limits**: Prevent resource exhaustion attacks
6. **Read-Only Root Filesystem**: Use `--read-only` when possible
7. **Drop All Capabilities**: Use `--cap-drop=all` by default
8. **Never Use Privileged Mode**: Avoid `--privileged` in production
9. **Externalize Secrets**: Use secret management, not environment variables
10. **Multi-Stage Builds**: Minimize final image size and attack surface
11. **Scan Base Images**: Regularly scan for CVEs in base images
12. **Use Trusted Registries**: Only pull from known, trusted registries

## Common Vulnerability Patterns

### CRITICAL - Container Escape

| Pattern | Detection | Impact |
|---------|-----------|--------|
| Docker socket mount | `/var/run/docker.sock` in volumes | Full host control |
| Privileged mode | `--privileged` flag | Full host control |
| Host PID namespace | `--pid=host` flag | Process escape |
| Host network | `--network=host` flag | Network isolation bypass |

### HIGH - Privilege Escalation

| Pattern | Detection | Impact |
|---------|-----------|--------|
| Running as root | Missing USER or `USER root` | Host privilege |
| Sensitive volumes | `/etc`, `/root`, `/home` mounts | Data exfiltration |
| Dangerous capabilities | `SYS_ADMIN`, `NET_ADMIN` | System control |
| Insecure base image | EOL or untrusted image | Known vulnerabilities |

### MEDIUM - Security Hygiene

| Pattern | Detection | Impact |
|---------|-----------|--------|
| Missing HEALTHCHECK | No `HEALTHCHECK` instruction | Detection gap |
| Unpinned base image | `:latest` tag | Unpredictable builds |
| No resource limits | Missing memory/CPU limits | Resource exhaustion |
| Exposed Docker API | Ports 2375/2376 | Remote code execution |

## Limitations

- **Static Analysis Only**: Cannot detect runtime security issues
- **File-Based Detection**: Cannot analyze built images or running containers
- **Configuration Focus**: Cannot detect application-level vulnerabilities
- **Pattern Matching**: May have false positives/negatives
- **No Image Scanning**: Cannot scan base image contents for CVEs

## References

- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CIS Docker Benchmark](https://www.cisecurity.org/cis-benchmarks)
- [NIST SP 800-190: Container Security Guide](https://nvd.nist.gov/publications/nist-sp/800-190)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
- [Docker-in-Docker Security Considerations](https://www.docker.com/blog/docker-can-now-run-within-docker/)

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/launchapp-dev/ao-skill-security/issues
- AO Documentation: https://github.com/launchapp-dev/ao-docs
