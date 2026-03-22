# Container Security Scanner

Analyze Dockerfiles, docker-compose files, and container configurations to detect security vulnerabilities and misconfigurations in containerized applications.

## Overview

This skill performs comprehensive static analysis of Docker-related files to identify security issues before container deployment. It detects dangerous patterns, insecure configurations, and common container security anti-patterns that could lead to privilege escalation, data exposure, or container compromise.

## Capabilities

- **Dockerfile Analysis**: Scan for security misconfigurations in Dockerfiles
- **Docker Compose Detection**: Identify risky service definitions
- **Configuration Review**: Check for insecure defaults and missing security controls
- **Base Image Verification**: Detect outdated and untrusted base images
- **Privilege Pattern Detection**: Identify containers running with excessive privileges
- **Volume Mount Analysis**: Detect sensitive host path mounts
- **Network Exposure Detection**: Identify dangerous port exposures and network policies
- **Health Check Verification**: Ensure containers have proper health monitoring
- **Severity Classification**: Rank findings by risk and exploitability
- **Structured Reports**: Output JSON findings with remediation guidance

## Scan Targets

### Critical Security Issues
- Exposed Docker socket (`-v /var/run/docker.sock`)
- Running as root user (missing USER instruction)
- Privileged container mode (`--privileged`)
- Sensitive volume mounts (`/etc`, `/var/run`, `/root`)
- Insecure capability grants (SYS_ADMIN, NET_ADMIN)

### High Priority Issues
- Use of `:latest` tag for base images
- Missing HEALTHCHECK instruction
- Running as root by default
- Insecure registry usage (HTTP)
- Exposed sensitive ports (22, 2375, 2376)

### Medium Priority Issues
- Missing resource limits (CPU, memory)
- No read-only root filesystem
- Insecure environment variable patterns
- Use of COPY instead of ADD in some contexts
- Missing USER or using root user

### Low Priority Issues
- Missing LABEL instructions
- Inefficient layer caching
- Use of `:latest` for application images
- Large image sizes from bloated base images

## Detection Patterns

### 1. Docker Socket Exposure

**Dockerfile:**
```dockerfile
# DANGEROUS - Exposes Docker daemon to container
docker run -v /var/run/docker.sock:/var/run/docker.sock myapp

# Equivalent in docker-compose
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

**Severity:** CRITICAL
**Impact:** Container can escape and control host Docker daemon

**Remediation:**
```dockerfile
# Remove the volume mount entirely
# If Docker-in-Docker is required, use DinD sidecar pattern
```

### 2. Running as Root

**Dockerfile:**
```dockerfile
# DANGEROUS - No USER instruction, defaults to root
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
CMD ["node", "index.js"]
```

**Severity:** HIGH
**Impact:** Container process has root privileges on host

**Remediation:**
```dockerfile
# Create and switch to non-root user
FROM node:18-alpine
RUN addgroup -g 1001 -S nodejs && adduser -S nextjs -u 1001
WORKDIR /app
COPY --chown=nextjs:nodejs package*.json ./
RUN npm ci --only=production && mv node_modules ./
COPY --chown=nextjs:nodejs . .
USER nextjs
CMD ["node", "index.js"]
```

### 3. Missing HEALTHCHECK

**Dockerfile:**
```dockerfile
# DANGEROUS - No health monitoring
FROM node:18-alpine
WORKDIR /app
COPY . .
CMD ["node", "index.js"]
```

**Severity:** HIGH
**Impact:** Orchestrator cannot detect hung or crashed containers

**Remediation:**
```dockerfile
# Add appropriate health check
FROM node:18-alpine
WORKDIR /app
COPY . .
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"
CMD ["node", "index.js"]
```

### 4. Use of :latest Tag

**Dockerfile:**
```dockerfile
# DANGEROUS - Unpredictable base image version
FROM node:latest
```

**Severity:** MEDIUM
**Impact:** Non-reproducible builds, potential for breaking changes

**Remediation:**
```dockerfile
# Pin to specific version
FROM node:18-alpine
# Or use digest for maximum security
FROM node:18-alpine@sha256:abc123...
```

### 5. Sensitive Volume Mounts

**docker-compose.yml:**
```yaml
# DANGEROUS - Sensitive host paths exposed
services:
  app:
    volumes:
      - /etc:/etc/readonly        # Host system files
      - /root:/root               # Host root home
      - /var/run/docker.sock:/var/run/docker.sock
```

**Severity:** CRITICAL (docker.sock), HIGH (system paths)
**Impact:** Potential container escape and host compromise

**Remediation:**
```yaml
services:
  app:
    # Remove sensitive mounts
    volumes:
      - ./data:/app/data          # Application data only
```

### 6. Insecure Base Images

**Dockerfile:**
```dockerfile
# DANGEROUS - Unmaintained and potentially vulnerable
FROM python:2.7                    # Python 2 is EOL
FROM ubuntu:14.04                  # Ubuntu 14.04 is EOL
FROM node:8                        # Node 8 is EOL
```

**Severity:** HIGH
**Impact:** Known CVEs and unpatched vulnerabilities

**Remediation:**
```dockerfile
# Use maintained, minimal images
FROM node:18-alpine
FROM python:3.11-slim
FROM ubuntu:22.04
```

### 7. Missing Resource Limits

**docker-compose.yml:**
```yaml
# DANGEROUS - No resource constraints
services:
  app:
    image: myapp
    # No deploy.resources.limits
```

**Severity:** MEDIUM
**Impact:** Resource exhaustion attacks, noisy neighbor issues

**Remediation:**
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

### 8. Privilege Escalation Patterns

**Dockerfile:**
```dockerfile
# DANGEROUS - Container can gain host privileges
docker run --privileged myapp

# DANGEROUS - Host network namespace exposed
docker run --network=host myapp

# DANGEROUS - Host PID namespace exposed
docker run --pid=host myapp
```

**Severity:** CRITICAL
**Impact:** Full host compromise possible

**Remediation:**
```dockerfile
# Run with minimal capabilities
docker run --cap-drop=all --security-opt=no-new-privileges myapp
```

### 9. Insecure Environment Variables

**docker-compose.yml:**
```yaml
# DANGEROUS - Secrets in plaintext
services:
  db:
    environment:
      - POSTGRES_PASSWORD=mysecretpassword
      - AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXXXX
```

**Severity:** HIGH
**Impact:** Credentials exposed in logs and images

**Remediation:**
```yaml
services:
  db:
    environment:
      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
    secrets:
      - db_password
```

### 10. Missing Read-Only Root Filesystem

**Dockerfile:**
```dockerfile
# DANGEROUS - Writable root filesystem
FROM node:18-alpine
WORKDIR /app
COPY . .
CMD ["node", "index.js"]
```

**Severity:** MEDIUM
**Impact:** Potential data corruption, easier exploitation

**Remediation:**
```bash
# Run with read-only root filesystem
docker run --read-only myapp

# In Dockerfile, specify read-only volumes
VOLUME ["/tmp", "/run"]
```

## Severity Levels

| Severity | Criteria | Example |
|----------|----------|---------|
| **CRITICAL** | Direct host escape vector | Docker socket mount, privileged mode |
| **HIGH** | Significant privilege or data exposure | Root user, sensitive volumes, insecure base image |
| **MEDIUM** | Security hygiene issue | Missing HEALTHCHECK, :latest tag, no resource limits |
| **LOW** | Best practice violation | Missing labels, inefficient caching |
| **INFO** | Optimization suggestion | Multi-stage build opportunities |

## Output Format

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

## Execution Steps

1. **Initialize Scanner**
   - Configure target file patterns
   - Set up detection rule engine
   - Initialize severity classification

2. **File Discovery**
   - Scan for Dockerfile files
   - Scan for docker-compose.yml and docker-compose.yaml
   - Scan for Containerfile variants
   - Check for .dockerignore

3. **Dockerfile Analysis**
   - Parse FROM instructions for base image issues
   - Check for USER instruction presence
   - Verify HEALTHCHECK instruction
   - Analyze RUN, COPY, ADD instructions
   - Check for privilege escalation patterns

4. **Compose File Analysis**
   - Parse service definitions
   - Analyze volume mounts
   - Check network configurations
   - Verify port exposures
   - Check resource limits
   - Analyze environment variables

5. **Generate Report**
   - Compile findings with metadata
   - Include file paths and line numbers
   - Provide actionable remediation guidance
   - Output structured JSON format

## Configuration

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
  
  # Severity thresholds
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
  
  # Recommended base images
  trusted_registries:
    - "docker.io"
    - "ghcr.io"
    - "registry.access.redhat.com"
  
  # Base image recommendations
  base_image_alternatives:
    "node:latest": "node:18-alpine"
    "node": "node:18-alpine"
    "python:latest": "python:3.11-slim"
    "ubuntu:latest": "ubuntu:22.04"
```

## Integration

### With AO Workflow

```yaml
phases:
  container-scan:
    mode: agent
    agent: ao.security.container-scanner
    directive: "Scan Dockerfiles and docker-compose files for security vulnerabilities"
    capabilities:
      reads_code: true
      produces_artifacts: true
```

### CI/CD Pipeline

```yaml
# GitHub Actions
- name: Container Security Scan
  run: ao skill run ao.security/container-scan --output json > container-report.json

- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: container-report
    path: container-report.json
```

### Pre-commit Hook

```bash
#!/bin/bash
# Run container security scan before commit
ao skill run ao.security/container-scan --staged
```

## Best Practices

1. **Always Specify USER**: Never run containers as root
2. **Pin Base Image Versions**: Use specific tags, not :latest
3. **Use Minimal Base Images**: Prefer alpine, slim, or distroless variants
4. **Add HEALTHCHECK**: Enable orchestrator health monitoring
5. **Set Resource Limits**: Prevent resource exhaustion
6. **Read-Only Filesystem**: Use --read-only when possible
7. **Drop All Capabilities**: Use --cap-drop=all by default
8. **No Privileged Mode**: Never use --privileged in production
9. **Separate Secrets**: Use secret management, not env vars
10. **Multi-Stage Builds**: Minimize final image size and attack surface

## References

- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CIS Docker Benchmark](https://www.cisecurity.org/cis-benchmarks)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
- [NIST Container Security Guide](https://nvd.nist.gov/publications/nist-sp/800-190)
