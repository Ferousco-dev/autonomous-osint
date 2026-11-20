"""Optional CLI wrappers for Maigret / Sherlock username enumeration (graceful fallback)."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..http_client import PoliteHTTPClient
from .base import (
    BaseCollector,
    CollectorResult,
    EntityRecord,
    FindingRecord,
    RelationshipRecord,
    SourceRecord,
)


class UsernameCliCollector(BaseCollector):
    name = "username_cli"
    description = "Optional Maigret/Sherlock CLI wrapper for public username enumeration (rate-limited, opt-in)."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        handle = target.strip().lstrip("@")
        res = CollectorResult(collector=self.name, target=handle)

        maigret_bin = shutil.which("maigret")
        sherlock_bin = shutil.which("sherlock")

        if not maigret_bin and not sherlock_bin:
            res.status = "skipped"
            res.error = (
                "Neither 'maigret' nor 'sherlock' is installed on PATH. "
                "Install optionally (e.g., `uv tool install maigret`) or rely on built-in web/GitHub collectors."
            )
            return res

        if maigret_bin:
            return self._run_maigret(maigret_bin, handle, res)
        assert sherlock_bin is not None
        return self._run_sherlock(sherlock_bin, handle, res)

    def _run_maigret(self, binary: str, handle: str, res: CollectorResult) -> CollectorResult:
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                proc = subprocess.run(
                    [
                        binary,
                        handle,
                        "--top-sites",
                        "50",
                        "--timeout",
                        "10",
                        "--no-progressbar",
                        "--folderoutput",
                        tmpdir,
                        "-J",
                        "simple",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=90,
                    check=False,
                )
                json_files = list(Path(tmpdir).glob("*.json"))
                if not json_files:
                    res.status = "empty" if proc.returncode == 0 else "error"
                    res.error = proc.stderr[:300]
                    return res

                data = json.loads(json_files[0].read_text(encoding="utf-8"))
                found_urls: list[str] = []
                for site, info in data.items():
                    if isinstance(info, dict) and info.get("status", {}).get("status") == "Claimed":
                        url = info.get("url_user") or ""
                        if url:
                            found_urls.append(url)
                            res.sources.append(
                                SourceRecord(
                                    url=url,
                                    title=f"{site} profile: {handle}",
                                    source_type="social_profile",
                                    snippet=f"Maigret matched username '{handle}' on {site}.",
                                )
                            )
                            res.entities.append(EntityRecord(name=f"{site}:{handle}", entity_type="social_account"))
                            res.relationships.append(
                                RelationshipRecord(
                                    source_entity=handle,
                                    relation="possible_account_on",
                                    target_entity=site,
                                    evidence_url=url,
                                    confidence="LOW",
                                )
                            )

                if not found_urls:
                    res.status = "empty"
                    return res

                res.findings.append(
                    FindingRecord(
                        category="Discovered Connections",
                        claim=(
                            f"Maigret (top 50 sites) found {len(found_urls)} public profiles matching handle '{handle}'. "
                            "Note: matching handles do not prove same-person identity without independent corroboration."
                        ),
                        confidence="LOW",
                        source_urls=found_urls[:10],
                        rationale="Automated username match; requires manual/cross-source identity corroboration.",
                    )
                )
                return res
            except Exception as exc:
                res.status = "error"
                res.error = str(exc)
                return res

    def _run_sherlock(self, binary: str, handle: str, res: CollectorResult) -> CollectorResult:
        try:
            proc = subprocess.run(
                [binary, handle, "--timeout", "10", "--print-found", "--no-color"],
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
            urls = [
                line.split(": ", 1)[1].strip()
                for line in proc.stdout.splitlines()
                if ": http" in line
            ]
            if not urls:
                res.status = "empty"
                return res
            for url in urls[:25]:
                res.sources.append(
                    SourceRecord(
                        url=url,
                        title=f"Sherlock match: {handle}",
                        source_type="social_profile",
                        snippet=f"Sherlock matched handle '{handle}'.",
                    )
                )
            res.findings.append(
                FindingRecord(
                    category="Discovered Connections",
                    claim=(
                        f"Sherlock found {len(urls)} public URLs matching handle '{handle}'. "
                        "Requires independent corroboration to confirm same-entity ownership."
                    ),
                    confidence="LOW",
                    source_urls=urls[:10],
                    rationale="Automated username enumeration.",
                )
            )
            return res
        except Exception as exc:
            res.status = "error"
            res.error = str(exc)
            return res
