#!/usr/bin/env python3
"""
NeuroSploit Benchmark Runner & Coverage Analyzer

Real execution of 104 CTF-style validation benchmarks:
  - Builds and starts each Docker challenge
  - Runs NeuroSploit autonomous agent against the target
  - Checks if the agent extracts the flag
  - Generates pass/fail results with detailed reporting

Usage:
  python3 tools/benchmark_runner.py run                           # Run all benchmarks
  python3 tools/benchmark_runner.py run --ids XBEN-050-24         # Run specific benchmark
  python3 tools/benchmark_runner.py run --tags xss sqli --level 1 # Filter by tag/level
  python3 tools/benchmark_runner.py run --dry-run                 # Show what would run
  python3 tools/benchmark_runner.py run --mode auto_pentest       # Thorough mode
  python3 tools/benchmark_runner.py coverage                      # Static coverage analysis
  python3 tools/benchmark_runner.py coverage --json               # Coverage as JSON
"""

import asyncio
import json
import os
import re
import signal
import subprocess
import sys
import time
import traceback
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import yaml

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ===========================================================================
# Docker Compose command detection
# ===========================================================================

def _detect_compose_cmd() -> List[str]:
    """Detect whether to use 'docker compose' (plugin) or 'docker-compose' (standalone)."""
    # Try plugin first: docker compose version
    try:
        r = subprocess.run(["docker", "compose", "version"], capture_output=True, timeout=5)
        if r.returncode == 0:
            return ["docker", "compose"]
    except Exception:
        pass
    # Try standalone: docker-compose version
    try:
        r = subprocess.run(["docker-compose", "version"], capture_output=True, timeout=5)
        if r.returncode == 0:
            return ["docker-compose"]
    except Exception:
        pass
    return []  # neither found


COMPOSE_CMD = _detect_compose_cmd()


# ===========================================================================
# Data Classes
# ===========================================================================

@dataclass
class BenchmarkConfig:
    """Parsed benchmark metadata."""
    id: str
    name: str
    description: str
    level: int
    tags: List[str]
    dir: str
    expected_flag: str
    service_name: str
    container_port: int
    is_fixed_port: bool
    fixed_host_port: Optional[int] = None


@dataclass
class BenchmarkResult:
    """Per-benchmark execution result."""
    benchmark_id: str
    benchmark_name: str
    level: int
    tags: List[str]
    status: str                          # pass, fail, error, timeout, skip
    flag_found: bool = False
    flag_value: Optional[str] = None
    expected_flag: str = ""
    flag_source: str = "none"            # finding_evidence, finding_response, etc.
    findings_count: int = 0
    findings_summary: List[Dict] = field(default_factory=list)
    duration_seconds: float = 0.0
    docker_build_time: float = 0.0
    docker_startup_time: float = 0.0
    agent_run_time: float = 0.0
    error_message: Optional[str] = None
    agent_logs: List[str] = field(default_factory=list)


# ===========================================================================
# Flag Detection
# ===========================================================================

# Matches flag{uuid-v4} format used by the benchmarks
FLAG_PATTERN = re.compile(r'flag\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}')
# Also match FLAG{sha256} format just in case
FLAG_PATTERN_SHA = re.compile(r'FLAG\{[a-f0-9]{64}\}')


class FlagDetector:
    """Multi-layer flag search in agent output."""

    @staticmethod
    def search_findings(findings, expected_flag: str) -> Tuple[bool, Optional[str], str]:
        """Search agent findings for the flag.
        Returns (found, flag_value, source_field).
        """
        search_fields = [
            ("evidence", "finding_evidence"),
            ("response", "finding_response"),
            ("payload", "finding_payload"),
            ("poc_code", "finding_poc"),
            ("description", "finding_description"),
            ("request", "finding_request"),
        ]
        for finding in findings:
            for attr, source in search_fields:
                text = getattr(finding, attr, "") or ""
                if not text:
                    continue
                # Exact match first
                if expected_flag and expected_flag in text:
                    return True, expected_flag, source
                # Pattern match
                m = FLAG_PATTERN.search(text)
                if m:
                    return True, m.group(0), source
                m = FLAG_PATTERN_SHA.search(text)
                if m:
                    return True, m.group(0), source
        return False, None, "none"

    @staticmethod
    def search_logs(logs: List[str], expected_flag: str) -> Tuple[bool, Optional[str]]:
        """Search agent log messages for the flag."""
        full_text = "\n".join(logs)
        if expected_flag and expected_flag in full_text:
            return True, expected_flag
        m = FLAG_PATTERN.search(full_text)
        if m:
            return True, m.group(0)
        m = FLAG_PATTERN_SHA.search(full_text)
        if m:
            return True, m.group(0)
        return False, None

    @staticmethod
    def search_report(report: Dict, expected_flag: str) -> Tuple[bool, Optional[str]]:
        """Search the full report dict for the flag."""
        try:
            text = json.dumps(report, default=str)
        except Exception:
            text = str(report)
        if expected_flag and expected_flag in text:
            return True, expected_flag
        m = FLAG_PATTERN.search(text)
        if m:
            return True, m.group(0)
        m = FLAG_PATTERN_SHA.search(text)
        if m:
            return True, m.group(0)
        return False, None

    @staticmethod
    async def http_crawl_for_flag(target_url: str, expected_flag: str) -> Tuple[bool, Optional[str]]:
        """Fallback: direct HTTP requests to common flag endpoints."""
        import aiohttp
        endpoints = [
            "/", "/flag", "/flag.txt", "/FLAG.txt", "/FLAG",
            "/api/flag", "/secret", "/secret.txt", "/admin",
            "/robots.txt", "/sitemap.xml",
        ]
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                for ep in endpoints:
                    try:
                        url = target_url.rstrip("/") + ep
                        async with session.get(url) as resp:
                            text = await resp.text()
                            if expected_flag and expected_flag in text:
                                return True, expected_flag
                            m = FLAG_PATTERN.search(text)
                            if m:
                                return True, m.group(0)
                            m = FLAG_PATTERN_SHA.search(text)
                            if m:
                                return True, m.group(0)
                    except Exception:
                        continue
        except Exception:
            pass
        return False, None


# ===========================================================================
# Docker Orchestrator
# ===========================================================================

class DockerOrchestrator:
    """Manages Docker Compose lifecycle for a single benchmark."""

    def __init__(self, benchmark_dir: str, project_name: str):
        self.benchmark_dir = benchmark_dir
        self.project_name = project_name
        self._started = False

    def _run(self, args: List[str], timeout: int = 120, capture: bool = True) -> subprocess.CompletedProcess:
        """Run a docker compose command."""
        cmd = COMPOSE_CMD + ["-p", self.project_name] + args
        return subprocess.run(
            cmd,
            cwd=self.benchmark_dir,
            timeout=timeout,
            capture_output=capture,
            text=True,
        )

    def build(self, timeout: int = 300) -> Tuple[bool, str]:
        """Build the benchmark containers."""
        try:
            result = self._run(["build"], timeout=timeout)
            if result.returncode != 0:
                err = (result.stderr or result.stdout or "unknown error")[-500:]
                return False, f"Build failed (exit {result.returncode}): {err}"
            return True, ""
        except subprocess.TimeoutExpired:
            return False, f"Build timed out after {timeout}s"
        except Exception as e:
            return False, str(e)

    def start(self, timeout: int = 180) -> Tuple[bool, str]:
        """Start containers and wait for healthchecks."""
        try:
            result = self._run(["up", "-d", "--wait"], timeout=timeout)
            if result.returncode != 0:
                err = (result.stderr or result.stdout or "unknown error")[-500:]
                return False, f"Start failed (exit {result.returncode}): {err}"
            self._started = True
            return True, ""
        except subprocess.TimeoutExpired:
            self._started = True  # might be partially started
            return False, f"Start timed out after {timeout}s (healthcheck may have failed)"
        except Exception as e:
            return False, str(e)

    def get_target_url(self, service_name: str, container_port: int,
                       is_fixed: bool, fixed_host_port: Optional[int]) -> Optional[str]:
        """Resolve the actual URL to test."""
        if is_fixed and fixed_host_port:
            return f"http://localhost:{fixed_host_port}"

        # Dynamic port: use docker compose port
        try:
            result = self._run(["port", service_name, str(container_port)], timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                # Output format: "0.0.0.0:55432" or ":::55432"
                addr = result.stdout.strip()
                if ":" in addr:
                    port = addr.rsplit(":", 1)[-1]
                    return f"http://localhost:{port}"
        except Exception:
            pass

        # Fallback: try to inspect containers for the port
        try:
            result = subprocess.run(
                COMPOSE_CMD + ["-p", self.project_name, "ps", "--format", "json"],
                cwd=self.benchmark_dir, capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                # Parse JSON output - may be one JSON per line
                for line in result.stdout.strip().split("\n"):
                    try:
                        info = json.loads(line)
                        publishers = info.get("Publishers") or []
                        for pub in publishers:
                            if pub.get("TargetPort") == container_port and pub.get("PublishedPort"):
                                return f"http://localhost:{pub['PublishedPort']}"
                    except (json.JSONDecodeError, TypeError):
                        continue
        except Exception:
            pass

        return None

    def cleanup(self, remove_images: bool = True) -> None:
        """Stop and remove all containers/volumes/images for this benchmark."""
        try:
            # --rmi all: also removes images built by this compose project
            rmi_flag = ["--rmi", "all"] if remove_images else []
            self._run(["down", "-v", "--remove-orphans", "-t", "10"] + rmi_flag, timeout=120)
        except Exception:
            pass
        # Force remove any lingering containers with the project prefix
        try:
            subprocess.run(
                COMPOSE_CMD + ["-p", self.project_name, "rm", "-f", "-s", "-v"],
                cwd=self.benchmark_dir, capture_output=True, timeout=30,
            )
        except Exception:
            pass

    def get_logs(self, service_name: str) -> str:
        """Get container logs for debugging."""
        try:
            result = self._run(["logs", service_name, "--tail", "100"], timeout=10)
            return result.stdout or ""
        except Exception:
            return ""


# ===========================================================================
# Benchmark Config Loader
# ===========================================================================

HTTP_PORTS = {80, 443, 3000, 4567, 5000, 5003, 8000, 8001, 8002, 8080, 8081, 8082, 9000}


def _parse_port_spec(port_spec) -> Tuple[int, bool, Optional[int]]:
    """Parse a docker-compose port specification.
    Returns: (container_port, is_fixed, fixed_host_port)
    """
    if isinstance(port_spec, int):
        return port_spec, False, None

    s = str(port_spec).strip().strip('"').strip("'").rstrip()
    if ":" in s:
        parts = s.split(":")
        # Could be "host:container" or "ip:host:container"
        if len(parts) == 3:
            host_port = int(parts[1])
            container_port = int(parts[2])
        else:
            host_port = int(parts[0])
            container_port = int(parts[1])
        return container_port, True, host_port
    else:
        return int(s), False, None


def _find_web_service(compose_data: Dict) -> Tuple[str, int, bool, Optional[int]]:
    """Find the web service from docker-compose data.
    Returns: (service_name, container_port, is_fixed, fixed_host_port)
    """
    services = compose_data.get("services", {})
    candidates = []

    for svc_name, svc_config in services.items():
        ports = svc_config.get("ports", [])
        if not ports:
            continue

        # Parse all ports for this service
        for port_spec in ports:
            container_port, is_fixed, fixed_host_port = _parse_port_spec(port_spec)
            has_http_healthcheck = False
            healthcheck = svc_config.get("healthcheck", {})
            if healthcheck:
                test = healthcheck.get("test", [])
                test_str = str(test) if isinstance(test, list) else str(test)
                has_http_healthcheck = "curl" in test_str or "http" in test_str

            candidates.append({
                "service_name": svc_name,
                "container_port": container_port,
                "is_fixed": is_fixed,
                "fixed_host_port": fixed_host_port,
                "has_http_healthcheck": has_http_healthcheck,
                "is_http_port": container_port in HTTP_PORTS,
            })

    if not candidates:
        # Fallback: pick first service
        first_svc = next(iter(services.keys()), "web")
        return first_svc, 80, False, None

    # Priority: HTTP healthcheck > HTTP port > first candidate
    candidates.sort(key=lambda c: (
        not c["has_http_healthcheck"],
        not c["is_http_port"],
    ))

    best = candidates[0]
    return best["service_name"], best["container_port"], best["is_fixed"], best["fixed_host_port"]


def _read_expected_flag(benchmark_dir: str) -> str:
    """Read FLAG from .env file."""
    env_path = os.path.join(benchmark_dir, ".env")
    if not os.path.exists(env_path):
        return ""
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("FLAG="):
                    value = line[5:].strip().strip('"').strip("'")
                    return value
    except Exception:
        pass
    return ""


def load_benchmark_configs(benchmarks_dir: str,
                           tag_filter: Optional[List[str]] = None,
                           level_filter: Optional[List[int]] = None,
                           id_filter: Optional[List[str]] = None) -> List[BenchmarkConfig]:
    """Load and parse all benchmark configurations with optional filtering."""
    configs = []
    bench_path = Path(benchmarks_dir)

    for d in sorted(bench_path.iterdir()):
        if not d.is_dir() or not d.name.startswith("XBEN-"):
            continue

        config_file = d / "benchmark.json"
        compose_file = d / "docker-compose.yml"
        if not config_file.exists() or not compose_file.exists():
            continue

        # Apply ID filter early
        if id_filter and d.name not in id_filter:
            continue

        try:
            # Load benchmark.json
            with open(config_file) as f:
                meta = json.load(f)

            name = meta.get("name", d.name)
            description = meta.get("description", "")
            level = int(meta.get("level", 1))
            tags = meta.get("tags", [])

            # Apply filters
            if level_filter and level not in level_filter:
                continue
            if tag_filter and not any(t in tags for t in tag_filter):
                continue

            # Read expected flag
            expected_flag = _read_expected_flag(str(d))

            # Parse docker-compose.yml
            with open(compose_file) as f:
                compose_data = yaml.safe_load(f)

            service_name, container_port, is_fixed, fixed_host_port = _find_web_service(compose_data)

            configs.append(BenchmarkConfig(
                id=d.name,
                name=name,
                description=description,
                level=level,
                tags=tags,
                dir=str(d),
                expected_flag=expected_flag,
                service_name=service_name,
                container_port=container_port,
                is_fixed_port=is_fixed,
                fixed_host_port=fixed_host_port,
            ))

        except Exception as e:
            print(f"  [WARN] Failed to load {d.name}: {e}")
            continue

    return configs


# ===========================================================================
# Report Generator
# ===========================================================================

class ReportGenerator:
    """Generates JSON and Markdown benchmark reports."""

    @staticmethod
    def generate_json(results: List[BenchmarkResult], output_path: str) -> None:
        """Write full results as JSON."""
        data = {
            "generated_at": datetime.utcnow().isoformat(),
            "total_benchmarks": len(results),
            "summary": ReportGenerator._compute_summary(results),
            "results": [asdict(r) for r in results],
        }
        # Don't include full agent_logs in main JSON (too large) - just count
        for entry in data["results"]:
            log_count = len(entry.get("agent_logs", []))
            entry["agent_log_count"] = log_count
            entry.pop("agent_logs", None)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    @staticmethod
    def _compute_summary(results: List[BenchmarkResult]) -> Dict:
        """Compute summary statistics."""
        total = len(results)
        passed = sum(1 for r in results if r.status == "pass")
        failed = sum(1 for r in results if r.status == "fail")
        errors = sum(1 for r in results if r.status == "error")
        timeouts = sum(1 for r in results if r.status == "timeout")
        skipped = sum(1 for r in results if r.status == "skip")

        # Level breakdown
        level_stats = defaultdict(lambda: {"total": 0, "passed": 0})
        for r in results:
            level_stats[r.level]["total"] += 1
            if r.status == "pass":
                level_stats[r.level]["passed"] += 1

        # Tag breakdown
        tag_stats = defaultdict(lambda: {"total": 0, "passed": 0})
        for r in results:
            for tag in r.tags:
                tag_stats[tag]["total"] += 1
                if r.status == "pass":
                    tag_stats[tag]["passed"] += 1

        # Flag source distribution
        source_counts = Counter(r.flag_source for r in results if r.flag_found)

        # Timing
        run_results = [r for r in results if r.status in ("pass", "fail")]
        avg_duration = (sum(r.duration_seconds for r in run_results) / len(run_results)) if run_results else 0
        total_duration = sum(r.duration_seconds for r in results)

        return {
            "pass_rate": f"{passed}/{total} ({passed/total*100:.1f}%)" if total else "0/0",
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "timeouts": timeouts,
            "skipped": skipped,
            "level_breakdown": dict(level_stats),
            "tag_breakdown": dict(tag_stats),
            "flag_source_distribution": dict(source_counts),
            "avg_duration_seconds": round(avg_duration, 1),
            "total_duration_seconds": round(total_duration, 1),
            "total_findings": sum(r.findings_count for r in results),
        }

    @staticmethod
    def generate_markdown(results: List[BenchmarkResult], output_path: str) -> None:
        """Write formatted Markdown summary."""
        summary = ReportGenerator._compute_summary(results)
        total = len(results)
        passed = summary["passed"]

        lines = [
            "# NeuroSploit Benchmark Results",
            "",
            f"**Date**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Total Benchmarks**: {total}",
            f"**Total Duration**: {summary['total_duration_seconds']:.0f}s ({summary['total_duration_seconds']/60:.1f}min)",
            "",
            "## Overall Results",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| **Pass Rate** | **{passed}/{total} ({passed/total*100:.1f}%)** |" if total else "",
            f"| Passed | {summary['passed']} |",
            f"| Failed | {summary['failed']} |",
            f"| Errors | {summary['errors']} |",
            f"| Timeouts | {summary['timeouts']} |",
            f"| Skipped | {summary['skipped']} |",
            f"| Total Findings | {summary['total_findings']} |",
            f"| Avg Duration | {summary['avg_duration_seconds']:.1f}s |",
            "",
            "## Level Breakdown",
            "",
            "| Level | Passed | Total | Rate |",
            "|-------|--------|-------|------|",
        ]

        for level in sorted(summary["level_breakdown"].keys()):
            stats = summary["level_breakdown"][level]
            label = {1: "Easy", 2: "Medium", 3: "Hard"}.get(level, str(level))
            rate = f"{stats['passed']/stats['total']*100:.1f}%" if stats["total"] else "N/A"
            lines.append(f"| {label} (L{level}) | {stats['passed']} | {stats['total']} | {rate} |")

        lines += [
            "",
            "## Tag Breakdown",
            "",
            "| Tag | Passed | Total | Rate |",
            "|-----|--------|-------|------|",
        ]

        sorted_tags = sorted(summary["tag_breakdown"].items(), key=lambda x: -x[1]["total"])
        for tag, stats in sorted_tags:
            rate = f"{stats['passed']/stats['total']*100:.1f}%" if stats["total"] else "N/A"
            lines.append(f"| {tag} | {stats['passed']} | {stats['total']} | {rate} |")

        if summary["flag_source_distribution"]:
            lines += [
                "",
                "## Flag Source Distribution",
                "",
                "| Source | Count |",
                "|--------|-------|",
            ]
            for source, count in sorted(summary["flag_source_distribution"].items(), key=lambda x: -x[1]):
                lines.append(f"| {source} | {count} |")

        lines += [
            "",
            "## Per-Benchmark Results",
            "",
            "| # | ID | Name | Level | Tags | Status | Flag | Findings | Duration |",
            "|---|-----|------|-------|------|--------|------|----------|----------|",
        ]

        for i, r in enumerate(results, 1):
            status_icon = {
                "pass": "PASS", "fail": "FAIL", "error": "ERR",
                "timeout": "T/O", "skip": "SKIP"
            }.get(r.status, r.status)
            flag_icon = "YES" if r.flag_found else "NO"
            tags_str = ", ".join(r.tags)
            name_short = r.benchmark_name[:40]
            lines.append(
                f"| {i} | {r.benchmark_id} | {name_short} | L{r.level} | {tags_str} | "
                f"{status_icon} | {flag_icon} | {r.findings_count} | {r.duration_seconds:.1f}s |"
            )

        # Error summary
        error_results = [r for r in results if r.error_message]
        if error_results:
            lines += [
                "",
                "## Errors",
                "",
            ]
            for r in error_results:
                lines.append(f"- **{r.benchmark_id}** ({r.status}): {r.error_message}")

        lines.append("")

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            f.write("\n".join(lines))

    @staticmethod
    def print_summary(results: List[BenchmarkResult]) -> None:
        """Print console summary."""
        summary = ReportGenerator._compute_summary(results)
        total = len(results)
        passed = summary["passed"]

        print()
        print("=" * 70)
        print("  NEUROSPLOIT BENCHMARK RESULTS")
        print("=" * 70)
        print()
        print(f"  Pass Rate:   {passed}/{total} ({passed/total*100:.1f}%)" if total else "  No results")
        print(f"  Passed: {summary['passed']}  |  Failed: {summary['failed']}  |  "
              f"Errors: {summary['errors']}  |  Timeouts: {summary['timeouts']}")
        print(f"  Total Findings: {summary['total_findings']}")
        print(f"  Total Duration: {summary['total_duration_seconds']:.0f}s "
              f"({summary['total_duration_seconds']/60:.1f}min)")
        print()

        print("  --- LEVEL BREAKDOWN ---")
        for level in sorted(summary["level_breakdown"].keys()):
            stats = summary["level_breakdown"][level]
            label = {1: "Easy", 2: "Medium", 3: "Hard"}.get(level, str(level))
            rate = f"{stats['passed']/stats['total']*100:.1f}%" if stats["total"] else "N/A"
            print(f"  Level {level} ({label}): {stats['passed']}/{stats['total']} ({rate})")

        print()
        print("  --- PER-BENCHMARK ---")
        for r in results:
            icon = {"pass": "+", "fail": "-", "error": "!", "timeout": "T", "skip": "S"}.get(r.status, "?")
            flag = "FLAG" if r.flag_found else "    "
            print(f"  [{icon}] {r.benchmark_id} L{r.level} {flag} "
                  f"findings={r.findings_count} {r.duration_seconds:.1f}s "
                  f"tags={','.join(r.tags)}")

        print()
        print("=" * 70)


# ===========================================================================
# Benchmark Runner (Main Orchestrator)
# ===========================================================================

class BenchmarkRunner:
    """Orchestrates real benchmark execution."""

    def __init__(
        self,
        benchmarks_dir: str = "/tmp/xbow-benchmarks/benchmarks",
        results_dir: str = "reports/benchmark_results",
        agent_mode: str = "full_auto",
        per_benchmark_timeout: int = 300,
        build_timeout: int = 300,
        startup_timeout: int = 180,
        tag_filter: Optional[List[str]] = None,
        level_filter: Optional[List[int]] = None,
        id_filter: Optional[List[str]] = None,
        resume: bool = True,
        dry_run: bool = False,
        keep_images: bool = False,
    ):
        self.benchmarks_dir = benchmarks_dir
        self.results_dir = os.path.join(PROJECT_ROOT, results_dir)
        self.logs_dir = os.path.join(self.results_dir, "logs")
        self.agent_mode = agent_mode
        self.per_benchmark_timeout = per_benchmark_timeout
        self.build_timeout = build_timeout
        self.startup_timeout = startup_timeout
        self.tag_filter = tag_filter
        self.level_filter = level_filter
        self.id_filter = id_filter
        self.resume = resume
        self.dry_run = dry_run
        self.keep_images = keep_images
        self._interrupted = False

    def _check_docker(self) -> bool:
        """Verify Docker Compose is available."""
        return len(COMPOSE_CMD) > 0

    def _progress_path(self) -> str:
        return os.path.join(self.results_dir, "progress.json")

    def _load_progress(self) -> Dict[str, Dict]:
        """Load previous results for resume."""
        path = self._progress_path()
        if not os.path.exists(path):
            return {}
        try:
            with open(path) as f:
                data = json.load(f)
            return data.get("completed", {})
        except Exception:
            return {}

    def _save_progress(self, completed: Dict[str, Dict]) -> None:
        """Save progress checkpoint."""
        os.makedirs(self.results_dir, exist_ok=True)
        data = {
            "run_id": datetime.utcnow().isoformat(),
            "agent_mode": self.agent_mode,
            "completed": completed,
        }
        with open(self._progress_path(), "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _save_benchmark_logs(self, benchmark_id: str, logs: List[str]) -> None:
        """Save per-benchmark agent logs."""
        os.makedirs(self.logs_dir, exist_ok=True)
        log_path = os.path.join(self.logs_dir, f"{benchmark_id}.log")
        with open(log_path, "w") as f:
            f.write("\n".join(logs))

    async def run_all(self) -> List[BenchmarkResult]:
        """Sequential execution of all benchmarks."""
        # Check Docker
        if not self._check_docker():
            print("ERROR: Docker Compose is not available.")
            print("  Install Docker Desktop or Docker Engine with compose plugin.")
            sys.exit(1)

        # Load configs
        print(f"\nLoading benchmarks from {self.benchmarks_dir}...")
        configs = load_benchmark_configs(
            self.benchmarks_dir,
            tag_filter=self.tag_filter,
            level_filter=self.level_filter,
            id_filter=self.id_filter,
        )
        print(f"Found {len(configs)} benchmarks" +
              (f" (filtered)" if self.tag_filter or self.level_filter or self.id_filter else ""))

        if not configs:
            print("No benchmarks match the filters.")
            return []

        # Dry run mode
        if self.dry_run:
            print(f"\n{'='*70}")
            print(f"  DRY RUN - {len(configs)} benchmarks would be executed")
            print(f"{'='*70}\n")
            for i, cfg in enumerate(configs, 1):
                print(f"  {i:3d}. {cfg.id} L{cfg.level} svc={cfg.service_name}:{cfg.container_port} "
                      f"{'fixed' if cfg.is_fixed_port else 'dynamic'} "
                      f"flag={'YES' if cfg.expected_flag else 'NO'} "
                      f"tags={','.join(cfg.tags)}")
            print(f"\n  Agent mode: {self.agent_mode}")
            print(f"  Per-benchmark timeout: {self.per_benchmark_timeout}s")
            print(f"  Build timeout: {self.build_timeout}s")
            return []

        # Resume support
        completed = {}
        if self.resume:
            completed = self._load_progress()
            if completed:
                print(f"Resuming: {len(completed)} benchmarks already completed")

        # Setup signal handler
        original_sigint = signal.getsignal(signal.SIGINT)

        def handle_interrupt(signum, frame):
            self._interrupted = True
            print("\n\n  [INTERRUPTED] Finishing current benchmark, then saving progress...")

        signal.signal(signal.SIGINT, handle_interrupt)

        # Ensure output dirs exist
        os.makedirs(self.results_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)

        results: List[BenchmarkResult] = []
        # Include previously completed results
        for cfg in configs:
            if cfg.id in completed:
                prev = completed[cfg.id]
                results.append(BenchmarkResult(
                    benchmark_id=prev["benchmark_id"],
                    benchmark_name=prev["benchmark_name"],
                    level=prev["level"],
                    tags=prev["tags"],
                    status=prev["status"],
                    flag_found=prev.get("flag_found", False),
                    flag_value=prev.get("flag_value"),
                    expected_flag=prev.get("expected_flag", ""),
                    flag_source=prev.get("flag_source", "none"),
                    findings_count=prev.get("findings_count", 0),
                    findings_summary=prev.get("findings_summary", []),
                    duration_seconds=prev.get("duration_seconds", 0),
                    error_message=prev.get("error_message"),
                ))

        remaining = [cfg for cfg in configs if cfg.id not in completed]
        total_remaining = len(remaining)
        run_idx = 0

        print(f"\n{'='*70}")
        print(f"  NEUROSPLOIT BENCHMARK RUNNER")
        print(f"  Mode: {self.agent_mode} | Timeout: {self.per_benchmark_timeout}s/benchmark")
        print(f"  Running {total_remaining}/{len(configs)} benchmarks")
        if completed:
            print(f"  Skipping {len(completed)} already completed (resume)")
        print(f"{'='*70}\n")

        for cfg in remaining:
            if self._interrupted:
                # Mark remaining as skipped
                results.append(BenchmarkResult(
                    benchmark_id=cfg.id,
                    benchmark_name=cfg.name,
                    level=cfg.level,
                    tags=cfg.tags,
                    status="skip",
                    expected_flag=cfg.expected_flag,
                    error_message="Interrupted by user",
                ))
                continue

            run_idx += 1
            print(f"\n[{run_idx}/{total_remaining}] {cfg.id} - {cfg.name[:50]}")
            print(f"  Level: {cfg.level} | Tags: {', '.join(cfg.tags)} | "
                  f"Service: {cfg.service_name}:{cfg.container_port}")

            result = await self._run_single_benchmark(cfg)
            results.append(result)

            # Save logs
            if result.agent_logs:
                self._save_benchmark_logs(cfg.id, result.agent_logs)

            # Update progress
            completed[cfg.id] = asdict(result)
            # Don't save massive logs in progress file
            if cfg.id in completed:
                completed[cfg.id].pop("agent_logs", None)
            self._save_progress(completed)

            # Print result
            icon = {"pass": "PASS", "fail": "FAIL", "error": "ERR",
                    "timeout": "T/O", "skip": "SKIP"}.get(result.status, "???")
            flag_str = f"flag={result.flag_source}" if result.flag_found else "no flag"
            print(f"  Result: [{icon}] {flag_str} | "
                  f"{result.findings_count} findings | {result.duration_seconds:.1f}s")
            if result.error_message:
                print(f"  Error: {result.error_message[:100]}")

        # Restore signal handler
        signal.signal(signal.SIGINT, original_sigint)

        # Generate reports
        timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")
        json_path = os.path.join(self.results_dir, f"results_{timestamp}.json")
        md_path = os.path.join(self.results_dir, f"results_{timestamp}.md")

        ReportGenerator.generate_json(results, json_path)
        ReportGenerator.generate_markdown(results, md_path)
        ReportGenerator.print_summary(results)

        print(f"\n  Reports saved:")
        print(f"    JSON: {json_path}")
        print(f"    Markdown: {md_path}")
        print(f"    Logs: {self.logs_dir}/")

        # Final Docker cleanup: prune dangling images, volumes, build cache
        if not self.keep_images:
            self._docker_prune()

        return results

    async def _run_single_benchmark(self, config: BenchmarkConfig) -> BenchmarkResult:
        """Execute a single benchmark: build → start → agent → check → cleanup."""
        orchestrator = DockerOrchestrator(
            config.dir,
            f"nsb-{config.id.lower()}"
        )
        agent_logs: List[str] = []
        start_time = time.time()

        try:
            # Phase 1: Build
            print(f"  [1/5] Building...")
            build_start = time.time()
            success, err = orchestrator.build(timeout=self.build_timeout)
            build_time = time.time() - build_start

            if not success:
                return BenchmarkResult(
                    benchmark_id=config.id,
                    benchmark_name=config.name,
                    level=config.level,
                    tags=config.tags,
                    status="error",
                    expected_flag=config.expected_flag,
                    duration_seconds=time.time() - start_time,
                    docker_build_time=build_time,
                    error_message=err,
                    agent_logs=agent_logs,
                )

            print(f"  [2/5] Starting (waiting for healthcheck)...")
            startup_start = time.time()
            success, err = orchestrator.start(timeout=self.startup_timeout)
            startup_time = time.time() - startup_start

            if not success:
                return BenchmarkResult(
                    benchmark_id=config.id,
                    benchmark_name=config.name,
                    level=config.level,
                    tags=config.tags,
                    status="error",
                    expected_flag=config.expected_flag,
                    duration_seconds=time.time() - start_time,
                    docker_build_time=build_time,
                    docker_startup_time=startup_time,
                    error_message=err,
                    agent_logs=agent_logs,
                )

            # Phase 3: Resolve URL
            print(f"  [3/5] Resolving target URL...")
            target_url = orchestrator.get_target_url(
                config.service_name, config.container_port,
                config.is_fixed_port, config.fixed_host_port,
            )

            if not target_url:
                return BenchmarkResult(
                    benchmark_id=config.id,
                    benchmark_name=config.name,
                    level=config.level,
                    tags=config.tags,
                    status="error",
                    expected_flag=config.expected_flag,
                    duration_seconds=time.time() - start_time,
                    docker_build_time=build_time,
                    docker_startup_time=startup_time,
                    error_message=f"Could not resolve target URL for {config.service_name}:{config.container_port}",
                    agent_logs=agent_logs,
                )

            print(f"  Target: {target_url}")

            # Phase 4: Run Agent
            print(f"  [4/5] Running agent ({self.agent_mode})...")
            agent_start = time.time()

            try:
                report, findings = await asyncio.wait_for(
                    self._run_agent(target_url, agent_logs),
                    timeout=self.per_benchmark_timeout,
                )
            except asyncio.TimeoutError:
                agent_time = time.time() - agent_start
                print(f"  Agent timed out after {agent_time:.0f}s")
                # Check partial results in logs
                found, flag_val = FlagDetector.search_logs(agent_logs, config.expected_flag)
                return BenchmarkResult(
                    benchmark_id=config.id,
                    benchmark_name=config.name,
                    level=config.level,
                    tags=config.tags,
                    status="pass" if found else "timeout",
                    flag_found=found,
                    flag_value=flag_val,
                    expected_flag=config.expected_flag,
                    flag_source="agent_log" if found else "none",
                    duration_seconds=time.time() - start_time,
                    docker_build_time=build_time,
                    docker_startup_time=startup_time,
                    agent_run_time=agent_time,
                    error_message=f"Agent timed out after {self.per_benchmark_timeout}s",
                    agent_logs=agent_logs,
                )
            except Exception as e:
                agent_time = time.time() - agent_start
                return BenchmarkResult(
                    benchmark_id=config.id,
                    benchmark_name=config.name,
                    level=config.level,
                    tags=config.tags,
                    status="error",
                    expected_flag=config.expected_flag,
                    duration_seconds=time.time() - start_time,
                    docker_build_time=build_time,
                    docker_startup_time=startup_time,
                    agent_run_time=agent_time,
                    error_message=f"Agent error: {str(e)[:200]}",
                    agent_logs=agent_logs,
                )

            agent_time = time.time() - agent_start

            # Phase 5: Flag Detection
            print(f"  [5/5] Checking for flag...")
            found = False
            flag_val = None
            flag_source = "none"

            # Layer 1: Findings
            found, flag_val, flag_source = FlagDetector.search_findings(
                findings, config.expected_flag
            )

            # Layer 2: Agent logs
            if not found:
                found, flag_val = FlagDetector.search_logs(agent_logs, config.expected_flag)
                if found:
                    flag_source = "agent_log"

            # Layer 3: Full report
            if not found and report:
                found, flag_val = FlagDetector.search_report(report, config.expected_flag)
                if found:
                    flag_source = "report"

            # Layer 4: HTTP crawl fallback
            if not found:
                found, flag_val = await FlagDetector.http_crawl_for_flag(
                    target_url, config.expected_flag
                )
                if found:
                    flag_source = "http_crawl"

            # Build findings summary
            findings_summary = []
            for f in findings:
                findings_summary.append({
                    "title": f.title,
                    "severity": f.severity,
                    "vulnerability_type": f.vulnerability_type,
                    "endpoint": f.affected_endpoint,
                })

            return BenchmarkResult(
                benchmark_id=config.id,
                benchmark_name=config.name,
                level=config.level,
                tags=config.tags,
                status="pass" if found else "fail",
                flag_found=found,
                flag_value=flag_val,
                expected_flag=config.expected_flag,
                flag_source=flag_source,
                findings_count=len(findings),
                findings_summary=findings_summary,
                duration_seconds=time.time() - start_time,
                docker_build_time=build_time,
                docker_startup_time=startup_time,
                agent_run_time=agent_time,
                agent_logs=agent_logs,
            )

        except Exception as e:
            return BenchmarkResult(
                benchmark_id=config.id,
                benchmark_name=config.name,
                level=config.level,
                tags=config.tags,
                status="error",
                expected_flag=config.expected_flag,
                duration_seconds=time.time() - start_time,
                error_message=f"Unexpected error: {str(e)[:200]}",
                agent_logs=agent_logs,
            )

        finally:
            print(f"  Cleaning up{' (removing images)' if not self.keep_images else ''}...")
            orchestrator.cleanup(remove_images=not self.keep_images)

    @staticmethod
    def _docker_prune() -> None:
        """Remove all dangling images, stopped containers, unused networks, and build cache."""
        print("\n  Running Docker cleanup (pruning unused data)...")
        freed_total = 0
        for cmd_label, cmd in [
            ("containers", ["docker", "container", "prune", "-f"]),
            ("images", ["docker", "image", "prune", "-f"]),
            ("volumes", ["docker", "volume", "prune", "-f"]),
            ("networks", ["docker", "network", "prune", "-f"]),
            ("build cache", ["docker", "builder", "prune", "-f", "--keep-storage", "1g"]),
        ]:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if result.returncode == 0:
                    # Parse reclaimed space from output (e.g., "Total reclaimed space: 2.3GB")
                    for line in (result.stdout or "").splitlines():
                        if "reclaimed" in line.lower():
                            print(f"    {cmd_label}: {line.strip()}")
            except Exception:
                pass
        print("  Docker cleanup complete.")

    async def _run_agent(self, target_url: str, agent_logs: List[str]) -> Tuple[Dict, list]:
        """Run the NeuroSploit autonomous agent against a target."""
        from backend.core.autonomous_agent import AutonomousAgent, OperationMode

        mode_map = {
            "full_auto": OperationMode.FULL_AUTO,
            "auto_pentest": OperationMode.AUTO_PENTEST,
            "recon_only": OperationMode.RECON_ONLY,
        }
        mode = mode_map.get(self.agent_mode, OperationMode.FULL_AUTO)

        async def log_callback(level: str, message: str):
            timestamp = datetime.utcnow().strftime("%H:%M:%S")
            entry = f"[{timestamp}] [{level.upper()}] {message}"
            agent_logs.append(entry)

        agent = AutonomousAgent(
            target=target_url,
            mode=mode,
            log_callback=log_callback,
        )

        async with agent:
            report = await agent.run()

        return report, list(agent.findings)


# ===========================================================================
# Coverage Analysis (preserved from original)
# ===========================================================================

TAG_TO_NEUROSPLOIT = {
    "xss": ["xss_reflected", "xss_stored", "xss_dom", "blind_xss", "mutation_xss"],
    "idor": ["idor", "bola"],
    "sqli": ["sqli_error", "sqli_union", "sqli_blind", "sqli_time"],
    "blind_sqli": ["sqli_blind", "sqli_time"],
    "ssti": ["ssti"],
    "command_injection": ["command_injection"],
    "ssrf": ["ssrf", "ssrf_cloud"],
    "lfi": ["lfi"],
    "path_traversal": ["path_traversal"],
    "xxe": ["xxe"],
    "insecure_deserialization": ["insecure_deserialization"],
    "csrf": ["csrf"],
    "jwt": ["jwt_manipulation"],
    "default_credentials": ["default_credentials"],
    "brute_force": ["brute_force"],
    "privilege_escalation": ["privilege_escalation"],
    "business_logic": ["business_logic"],
    "information_disclosure": ["information_disclosure", "sensitive_data_exposure"],
    "arbitrary_file_upload": ["file_upload"],
    "race_condition": ["race_condition"],
    "nosqli": ["nosql_injection"],
    "graphql": ["graphql_injection", "graphql_introspection"],
    "smuggling_desync": ["http_smuggling"],
    "http_method_tamper": ["http_methods"],
    "crypto": ["weak_encryption", "weak_hashing"],
    "cve": [],
    "ssh": [],
}

_HARDCODED_TYPES = {
    "sqli_error", "sqli_union", "sqli_blind", "sqli_time",
    "command_injection", "ssti", "nosql_injection", "ldap_injection",
    "xpath_injection", "graphql_injection", "crlf_injection",
    "header_injection", "email_injection", "expression_language_injection",
    "log_injection", "html_injection", "csv_injection", "orm_injection",
    "xss_reflected", "xss_stored", "xss_dom", "blind_xss", "mutation_xss",
    "lfi", "rfi", "path_traversal", "xxe", "file_upload",
    "arbitrary_file_read", "arbitrary_file_delete", "zip_slip",
    "ssrf", "ssrf_cloud", "csrf", "cors_misconfig",
    "auth_bypass", "jwt_manipulation", "session_fixation",
    "weak_password", "default_credentials", "brute_force",
    "two_factor_bypass", "oauth_misconfiguration",
    "idor", "bola", "bfla", "privilege_escalation",
    "mass_assignment", "forced_browsing",
    "clickjacking", "open_redirect", "dom_clobbering",
    "postmessage_vulnerability", "websocket_hijacking",
    "prototype_pollution", "css_injection", "tabnabbing",
    "security_headers", "ssl_issues", "http_methods",
    "directory_listing", "debug_mode", "exposed_admin_panel",
    "exposed_api_docs", "insecure_cookie_flags",
    "http_smuggling", "cache_poisoning",
    "race_condition", "business_logic", "rate_limit_bypass",
    "parameter_pollution", "type_juggling", "insecure_deserialization",
    "subdomain_takeover", "host_header_injection", "timing_attack",
    "improper_error_handling", "sensitive_data_exposure",
    "information_disclosure", "api_key_exposure",
    "source_code_disclosure", "backup_file_exposure",
    "version_disclosure",
    "weak_encryption", "weak_hashing", "weak_random",
    "cleartext_transmission", "vulnerable_dependency",
    "outdated_component", "insecure_cdn", "container_escape",
    "s3_bucket_misconfiguration", "cloud_metadata_exposure",
    "serverless_misconfiguration", "graphql_introspection",
    "graphql_dos", "rest_api_versioning", "soap_injection",
    "api_rate_limiting", "excessive_data_exposure",
}

CAPABILITY_SCORES = {
    "sqli_error": 3, "sqli_union": 3, "sqli_blind": 3, "sqli_time": 3,
    "command_injection": 3, "ssti": 3, "nosql_injection": 3,
    "ldap_injection": 3, "xpath_injection": 3, "graphql_injection": 3,
    "crlf_injection": 3, "header_injection": 3, "email_injection": 2,
    "expression_language_injection": 3, "log_injection": 2,
    "html_injection": 3, "csv_injection": 2, "orm_injection": 2,
    "xss_reflected": 3, "xss_stored": 3, "xss_dom": 2,
    "blind_xss": 2, "mutation_xss": 2,
    "lfi": 3, "rfi": 3, "path_traversal": 3, "xxe": 3,
    "file_upload": 3, "arbitrary_file_read": 2,
    "arbitrary_file_delete": 2, "zip_slip": 2,
    "ssrf": 3, "ssrf_cloud": 3, "csrf": 2, "cors_misconfig": 2,
    "auth_bypass": 2, "jwt_manipulation": 3, "session_fixation": 2,
    "weak_password": 2, "default_credentials": 2, "brute_force": 2,
    "two_factor_bypass": 1, "oauth_misconfiguration": 1,
    "idor": 3, "bola": 2, "bfla": 2, "privilege_escalation": 2,
    "mass_assignment": 2, "forced_browsing": 2,
    "clickjacking": 2, "open_redirect": 3, "dom_clobbering": 1,
    "postmessage_vulnerability": 1, "websocket_hijacking": 1,
    "prototype_pollution": 2, "css_injection": 1, "tabnabbing": 1,
    "security_headers": 2, "ssl_issues": 2, "http_methods": 2,
    "directory_listing": 2, "debug_mode": 2, "exposed_admin_panel": 2,
    "exposed_api_docs": 2, "insecure_cookie_flags": 2,
    "http_smuggling": 2, "cache_poisoning": 2,
    "race_condition": 2, "business_logic": 1, "rate_limit_bypass": 2,
    "parameter_pollution": 2, "type_juggling": 2,
    "insecure_deserialization": 2, "subdomain_takeover": 2,
    "host_header_injection": 2, "timing_attack": 1,
    "improper_error_handling": 1, "sensitive_data_exposure": 2,
    "information_disclosure": 2, "api_key_exposure": 2,
    "source_code_disclosure": 2, "backup_file_exposure": 2,
    "version_disclosure": 2,
    "weak_encryption": 1, "weak_hashing": 1, "weak_random": 1,
    "cleartext_transmission": 1, "vulnerable_dependency": 1,
    "outdated_component": 1, "insecure_cdn": 1, "container_escape": 1,
    "s3_bucket_misconfiguration": 2, "cloud_metadata_exposure": 2,
    "serverless_misconfiguration": 1, "graphql_introspection": 2,
    "graphql_dos": 1, "rest_api_versioning": 1, "soap_injection": 2,
    "api_rate_limiting": 1, "excessive_data_exposure": 1,
}


def load_neurosploit_types() -> Tuple[Set[str], Dict]:
    """Load NeuroSploit's 100 vulnerability types from registry."""
    try:
        from backend.core.vuln_engine.registry import VulnerabilityRegistry
        reg = VulnerabilityRegistry()
        types = set(reg.VULNERABILITY_INFO.keys())
        return types, reg.VULNERABILITY_INFO
    except ImportError:
        return _HARDCODED_TYPES, {}


def load_benchmarks(benchmarks_dir: str) -> List[Dict]:
    """Load all benchmark configurations (for coverage analysis)."""
    benchmarks = []
    bench_path = Path(benchmarks_dir)

    for d in sorted(bench_path.iterdir()):
        if not d.is_dir() or not d.name.startswith("XBEN-"):
            continue

        config_file = d / "benchmark.json"
        if not config_file.exists():
            continue

        try:
            with open(config_file) as f:
                config = json.load(f)
            config["id"] = d.name
            config["dir"] = str(d)
            benchmarks.append(config)
        except (json.JSONDecodeError, KeyError):
            continue

    return benchmarks


def analyze_coverage(benchmarks: List[Dict], ns_types: Set[str]) -> Dict:
    """Analyze NeuroSploit coverage of benchmarks."""
    tag_counter = Counter()
    for bench in benchmarks:
        tags = bench.get("tags", [])
        for tag in tags:
            tag_counter[tag] += 1

    covered_tags = set()
    uncovered_tags = set()
    tag_mapping = {}

    for tag in tag_counter:
        ns_mapped = TAG_TO_NEUROSPLOIT.get(tag, [])
        if ns_mapped:
            matched = [t for t in ns_mapped if t in ns_types]
            if matched:
                covered_tags.add(tag)
                tag_mapping[tag] = matched
            else:
                uncovered_tags.add(tag)
                tag_mapping[tag] = []
        else:
            uncovered_tags.add(tag)
            tag_mapping[tag] = []

    fully_covered = 0
    partially_covered = 0
    not_covered = 0
    benchmark_results = []

    for bench in benchmarks:
        tags = bench.get("tags", [])
        mapped_tags = [t for t in tags if t in covered_tags]
        coverage_pct = (len(mapped_tags) / len(tags) * 100) if tags else 0

        best_capability = 0
        for tag in tags:
            for ns_type in tag_mapping.get(tag, []):
                cap = CAPABILITY_SCORES.get(ns_type, 0)
                if cap > best_capability:
                    best_capability = cap

        status = "fully_covered" if len(mapped_tags) == len(tags) else (
            "partially_covered" if mapped_tags else "not_covered"
        )

        if status == "fully_covered":
            fully_covered += 1
        elif status == "partially_covered":
            partially_covered += 1
        else:
            not_covered += 1

        benchmark_results.append({
            "id": bench["id"],
            "name": bench.get("name", ""),
            "level": bench.get("level", ""),
            "tags": tags,
            "mapped_ns_types": [t for tag in tags for t in tag_mapping.get(tag, [])],
            "coverage_pct": coverage_pct,
            "capability_score": best_capability,
            "status": status,
        })

    total_tags = len(tag_counter)
    covered_count = len(covered_tags)
    tag_coverage_pct = (covered_count / total_tags * 100) if total_tags else 0

    total_benchmarks = len(benchmarks)
    benchmark_coverage_pct = (fully_covered / total_benchmarks * 100) if total_benchmarks else 0
    benchmark_any_coverage_pct = ((fully_covered + partially_covered) / total_benchmarks * 100) if total_benchmarks else 0

    level_stats = defaultdict(lambda: {"total": 0, "covered": 0})
    for br in benchmark_results:
        level = str(br["level"])
        level_stats[level]["total"] += 1
        if br["status"] in ("fully_covered", "partially_covered"):
            level_stats[level]["covered"] += 1

    total_cap = 0
    max_cap = 0
    for br in benchmark_results:
        total_cap += br["capability_score"]
        max_cap += 3

    capability_accuracy = (total_cap / max_cap * 100) if max_cap else 0

    return {
        "total_benchmarks": total_benchmarks,
        "total_tags": total_tags,
        "covered_tags": covered_count,
        "uncovered_tags": total_tags - covered_count,
        "tag_coverage_pct": round(tag_coverage_pct, 1),
        "fully_covered_benchmarks": fully_covered,
        "partially_covered_benchmarks": partially_covered,
        "not_covered_benchmarks": not_covered,
        "benchmark_full_coverage_pct": round(benchmark_coverage_pct, 1),
        "benchmark_any_coverage_pct": round(benchmark_any_coverage_pct, 1),
        "capability_weighted_accuracy": round(capability_accuracy, 1),
        "ns_total_types": len(ns_types),
        "tag_mapping": tag_mapping,
        "tag_counter": dict(tag_counter),
        "covered_tag_list": sorted(covered_tags),
        "uncovered_tag_list": sorted(uncovered_tags),
        "level_stats": dict(level_stats),
        "benchmark_results": benchmark_results,
    }


def print_coverage_report(analysis: Dict):
    """Print formatted coverage report."""
    print()
    print("=" * 70)
    print("  NEUROSPLOIT BENCHMARK COVERAGE ANALYSIS")
    print("=" * 70)
    print()

    print(f"  Total Benchmarks:        {analysis['total_benchmarks']}")
    print(f"  NeuroSploit Vuln Types:  {analysis['ns_total_types']}")
    print()

    print("  --- TAG COVERAGE ---")
    print(f"  Unique Tags in Benchmarks: {analysis['total_tags']}")
    print(f"  Tags Mapped to NS Types:   {analysis['covered_tags']} / {analysis['total_tags']}")
    print(f"  Tag Coverage:              {analysis['tag_coverage_pct']}%")
    print()

    print(f"  Covered Tags:    {', '.join(analysis['covered_tag_list'])}")
    print(f"  Uncovered Tags:  {', '.join(analysis['uncovered_tag_list'])}")
    print()

    print("  --- BENCHMARK COVERAGE ---")
    print(f"  Fully Covered:     {analysis['fully_covered_benchmarks']} / {analysis['total_benchmarks']} ({analysis['benchmark_full_coverage_pct']}%)")
    print(f"  Partially Covered: {analysis['partially_covered_benchmarks']} / {analysis['total_benchmarks']}")
    print(f"  Not Covered:       {analysis['not_covered_benchmarks']} / {analysis['total_benchmarks']}")
    print(f"  Any Coverage:      {analysis['benchmark_any_coverage_pct']}%")
    print()

    print("  --- DETECTION CAPABILITY ---")
    print(f"  Capability-Weighted Accuracy: {analysis['capability_weighted_accuracy']}%")
    print(f"  (Score: 3=full tester+payloads+AI, 2=tester+basic, 1=inspection, 0=none)")
    print()

    print("  --- LEVEL BREAKDOWN ---")
    for level in sorted(analysis["level_stats"].keys()):
        stats = analysis["level_stats"][level]
        pct = round(stats["covered"] / stats["total"] * 100, 1) if stats["total"] else 0
        label = {"1": "Easy", "2": "Medium", "3": "Hard"}.get(level, level)
        print(f"  Level {level} ({label}): {stats['covered']}/{stats['total']} covered ({pct}%)")
    print()

    print("  --- TAG FREQUENCY ---")
    sorted_tags = sorted(analysis["tag_counter"].items(), key=lambda x: -x[1])
    for tag, count in sorted_tags:
        mapped = analysis["tag_mapping"].get(tag, [])
        status = "OK" if mapped else "NO MAP"
        ns_str = ", ".join(mapped[:3]) if mapped else "-"
        print(f"  {tag:30s}  {count:3d} benchmarks  [{status}]  -> {ns_str}")
    print()

    print("  --- PER-BENCHMARK DETAIL ---")
    for br in analysis["benchmark_results"]:
        cap_str = ["_", "L", "M", "H"][br["capability_score"]]
        status_sym = {"fully_covered": "+", "partially_covered": "~", "not_covered": "-"}[br["status"]]
        print(f"  [{status_sym}][{cap_str}] {br['id']} L{br['level']} {br['coverage_pct']:5.0f}%  tags={','.join(br['tags'])}")

    print()
    print("=" * 70)
    print(f"  FINAL ACCURACY: {analysis['capability_weighted_accuracy']}% capability-weighted")
    print(f"  TYPE COVERAGE:  {analysis['tag_coverage_pct']}% of benchmark vuln tags")
    print(f"  FULL COVERAGE:  {analysis['benchmark_full_coverage_pct']}% of benchmarks fully covered")
    print(f"  ANY COVERAGE:   {analysis['benchmark_any_coverage_pct']}% of benchmarks with any coverage")
    print("=" * 70)
    print()


# ===========================================================================
# CLI Entry Point
# ===========================================================================

def main():
    """Main CLI entry point with subcommands."""
    import argparse

    parser = argparse.ArgumentParser(
        description="NeuroSploit Benchmark Runner & Coverage Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s run                                   Run all 104 benchmarks
  %(prog)s run --ids XBEN-050-24                 Run specific benchmark
  %(prog)s run --tags xss sqli --level 1         Filter by tag and level
  %(prog)s run --mode auto_pentest --timeout 600 Thorough mode, 10min timeout
  %(prog)s run --dry-run                         Show what would run
  %(prog)s run --no-resume                       Start fresh (ignore progress)
  %(prog)s coverage                              Static coverage analysis
  %(prog)s coverage --json                       Coverage output as JSON
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command")

    # 'run' subcommand
    run_parser = subparsers.add_parser("run", help="Execute benchmarks against live targets")
    run_parser.add_argument("--benchmarks", default="/tmp/xbow-benchmarks/benchmarks",
                           help="Path to benchmarks directory")
    run_parser.add_argument("--results-dir", default="reports/benchmark_results",
                           help="Output directory for results")
    run_parser.add_argument("--mode", choices=["full_auto", "auto_pentest", "recon_only"],
                           default="full_auto", help="Agent operation mode")
    run_parser.add_argument("--timeout", type=int, default=300,
                           help="Per-benchmark agent timeout in seconds (default: 300)")
    run_parser.add_argument("--build-timeout", type=int, default=300,
                           help="Docker build timeout in seconds (default: 300)")
    run_parser.add_argument("--startup-timeout", type=int, default=180,
                           help="Docker startup timeout in seconds (default: 180)")
    run_parser.add_argument("--tags", nargs="+", help="Filter by benchmark tags")
    run_parser.add_argument("--level", nargs="+", type=int, help="Filter by level (1, 2, 3)")
    run_parser.add_argument("--ids", nargs="+", help="Filter by benchmark IDs")
    run_parser.add_argument("--no-resume", action="store_true",
                           help="Start fresh (ignore previous progress)")
    run_parser.add_argument("--dry-run", action="store_true",
                           help="Show which benchmarks would run without executing")
    run_parser.add_argument("--keep-images", action="store_true",
                           help="Keep Docker images after each benchmark (faster re-runs, uses more disk)")

    # 'coverage' subcommand
    cov_parser = subparsers.add_parser("coverage", help="Static coverage analysis (no execution)")
    cov_parser.add_argument("--benchmarks", default="/tmp/xbow-benchmarks/benchmarks",
                           help="Path to benchmarks directory")
    cov_parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    # Default to 'coverage' if no subcommand (backward compatible)
    if args.command == "run":
        if not os.path.isdir(args.benchmarks):
            print(f"Error: Benchmarks directory not found: {args.benchmarks}")
            sys.exit(1)

        runner = BenchmarkRunner(
            benchmarks_dir=args.benchmarks,
            results_dir=args.results_dir,
            agent_mode=args.mode,
            per_benchmark_timeout=args.timeout,
            build_timeout=args.build_timeout,
            startup_timeout=args.startup_timeout,
            tag_filter=args.tags,
            level_filter=args.level,
            id_filter=args.ids,
            resume=not args.no_resume,
            dry_run=args.dry_run,
            keep_images=args.keep_images,
        )
        asyncio.run(runner.run_all())

    else:
        # Coverage analysis (default or explicit 'coverage' subcommand)
        benchmarks_dir = getattr(args, "benchmarks", "/tmp/xbow-benchmarks/benchmarks")
        output_json = getattr(args, "json", False)

        if not os.path.isdir(benchmarks_dir):
            print(f"Error: Benchmarks directory not found: {benchmarks_dir}")
            sys.exit(1)

        benchmarks = load_benchmarks(benchmarks_dir)
        if not benchmarks:
            print("Error: No benchmarks found")
            sys.exit(1)

        ns_types, ns_info = load_neurosploit_types()
        analysis = analyze_coverage(benchmarks, ns_types)

        if output_json:
            output = {k: v for k, v in analysis.items() if k != "benchmark_results"}
            output["benchmark_summary"] = [
                {"id": br["id"], "coverage": br["coverage_pct"], "capability": br["capability_score"]}
                for br in analysis["benchmark_results"]
            ]
            print(json.dumps(output, indent=2))
        else:
            print_coverage_report(analysis)


if __name__ == "__main__":
    main()
