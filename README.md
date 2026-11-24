# Sensitive Files & Config Checker

A targeted Python reconnaissance tool designed to detect publicly exposed configuration files, version control metadata, and database backups while filtering out false positives caused by Soft 404 responses.

## Key Features

- **Soft 404 Baseline Calibration:** Probes a randomized non-existent path before scanning to fingerprint custom `200 OK` error pages and eliminate false positives.
- **Memory-Safe Stream Inspection:** Uses HTTP streaming (`stream=True`) to fetch only the first **512 bytes** of each target file, preventing memory exhaustion on large SQL dumps or ZIP archives.
- **Byte-Level Signature Matching:** Verifies authentic file headers and patterns (e.g., `PK\x03\x04` for ZIP archives, `Bud1` for macOS `.DS_Store`, `[core]` for `.git/config`, and key-value assignments for `.env`).
- **Restricted Resource Detection:** Flags `403 Forbidden` responses to highlight existing files protected by server permissions.

## Checked Artifacts

| Path | Target Description | Severity |
| :--- | :--- | :--- |
| `/.env` | Environment variables & API secrets | `CRITICAL` |
| `/backup.zip` | Exposed source/site archive | `CRITICAL` |
| `/dump.sql` | Unprotected SQL database dump | `CRITICAL` |
| `/.git/config` | Git repository configuration | `HIGH` |
| `/.git/HEAD` | Git HEAD reference | `HIGH` |
| `/docker-compose.yml` | Container infrastructure config | `HIGH` |
| `/.DS_Store` | macOS directory index metadata | `MEDIUM` |
| `/phpinfo.php` | Exposed PHP environment diagnostics | `MEDIUM` |

## Requirements

- Python 3.9+
- `requests`

## Installation & Usage

1. Install the dependency:
   ```bash
   pip3 install requests
   ```

2. Scan one or multiple target URLs:
   ```bash
   python3 config_checker.py [https://example.com](https://example.com)
   ```

3. **Safe Local Testing:**
   ```bash
   mkdir -p /tmp/vuln_test && cd /tmp/vuln_test
   echo "DB_PASSWORD=super_secret_123" > .env
   python3 -m http.server 8080
   ```
   In a separate terminal:
   ```bash
   python3 config_checker.py http://localhost:8080
   ```

## Disclaimer

This tool is built strictly for educational purposes and authorized security auditing. Do not scan targets without explicit permission.