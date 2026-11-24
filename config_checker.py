from __future__ import annotations

import sys
import warnings
from dataclasses import dataclass
from typing import ClassVar

import requests

warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")


class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


@dataclass
class Finding:
    path: str
    url: str
    status_code: int
    severity: str
    details: str


class ConfigChecker:
    # path -> (description, severity, signature_substrings_or_bytes)
    SENSITIVE_PATHS: ClassVar[dict[str, tuple[str, str, tuple[bytes, ...]]]] = {
        "/.env": ("Environment variables file", "CRITICAL", (b"=", b"KEY", b"SECRET", b"DB_", b"PASSWORD")),
        "/.git/config": ("Git repository configuration", "HIGH", (b"[core]", b"[remote")),
        "/.git/HEAD": ("Git HEAD reference", "HIGH", (b"ref: refs/",)),
        "/.DS_Store": ("macOS directory metadata", "MEDIUM", (b"Bud1",)),
        "/docker-compose.yml": ("Docker Compose configuration", "HIGH", (b"services:", b"version:")),
        "/phpinfo.php": ("Exposed PHP configuration info", "MEDIUM", (b"PHP Version", b"phpinfo()")),
        "/backup.zip": ("Exposed ZIP archive", "CRITICAL", (b"PK\x03\x04",)),
        "/dump.sql": ("Exposed SQL database dump", "CRITICAL", (b"CREATE TABLE", b"INSERT INTO", b"-- MySQL", b"-- PostgreSQL")),
    }

    def __init__(self, timeout: int = 6):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (SecurityConfigAuditor/1.0)"
        })

    def _normalize_url(self, url: str) -> str:
        url = url.strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            return f"https://{url}"
        return url

    def _get_soft_404_baseline(self, base_url: str) -> tuple[int, int]:
        """Request a non-existent path to detect custom 200 OK error pages."""
        probe_url = f"{base_url}/non-existent-audit-probe-948271"
        try:
            resp = self.session.get(probe_url, timeout=self.timeout, allow_redirects=True)
            return resp.status_code, len(resp.content)
        except requests.RequestException:
            return 404, 0

    def _fetch_snippet(self, url: str, max_bytes: int = 512) -> tuple[int, str, bytes] | None:
        """Download only the first 512 bytes to avoid pulling huge backups into RAM."""
        try:
            with self.session.get(url, timeout=self.timeout, stream=True, allow_redirects=False) as resp:
                content_type = resp.headers.get("Content-Type", "").lower()
                chunk = next(resp.iter_content(chunk_size=max_bytes), b"")
                return resp.status_code, content_type, chunk
        except requests.RequestException:
            return None

    def scan(self, target_url: str) -> list[Finding]:
        base_url = self._normalize_url(target_url)
        findings: list[Finding] = []

        baseline_status, baseline_size = self._get_soft_404_baseline(base_url)

        for path, (description, severity, signatures) in self.SENSITIVE_PATHS.items():
            full_url = f"{base_url}{path}"
            result = self._fetch_snippet(full_url)

            if not result:
                continue

            status, content_type, snippet = result

            # 403 means the file exists on disk, though access is restricted
            if status == 403:
                findings.append(Finding(
                    path=path,
                    url=full_url,
                    status_code=403,
                    severity="INFO",
                    details=f"{description} exists (Access Forbidden)"
                ))
                continue

            if status != 200 or not snippet:
                continue

            # Filter out HTML pages masquerading as config files (Soft 404)
            if "text/html" in content_type and path != "/phpinfo.php":
                continue

            if baseline_status == 200 and abs(len(snippet) - baseline_size) < 50:
                continue

            # Verify file signature in the first 512 bytes
            if any(sig in snippet for sig in signatures):
                findings.append(Finding(
                    path=path,
                    url=full_url,
                    status_code=200,
                    severity=severity,
                    details=f"EXPOSED: {description}"
                ))

        return findings


def print_findings(target: str, findings: list[Finding]) -> None:
    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Target:{Colors.RESET} {target}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")

    if not findings:
        print(f"{Colors.GREEN}✓ No exposed sensitive files or configs detected.{Colors.RESET}\n")
        return

    for item in findings:
        color = Colors.RED if item.severity in ("CRITICAL", "HIGH") else Colors.YELLOW
        print(f"  {color}[{item.severity}]{Colors.RESET} {item.url} (HTTP {item.status_code})")
        print(f"       ↳ {item.details}")
    print()


if __name__ == "__main__":
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["example.com"]
    checker = ConfigChecker()

    for domain in targets:
        results = checker.scan(domain)
        print_findings(domain, results)