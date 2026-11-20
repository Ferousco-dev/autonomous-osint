"""Domain, IP, DNS, Certificate Transparency, and Wayback Machine collectors (no API keys)."""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
from urllib.parse import urlparse

from ..http_client import PoliteHTTPClient
from .base import (
    BaseCollector,
    CollectorResult,
    EntityRecord,
    FindingRecord,
    LeadRecord,
    RelationshipRecord,
    SourceRecord,
)


def _extract_host(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return urlparse(target).netloc.split(":")[0].lower()
    if "@" in target:
        return target.split("@", 1)[1].lower()
    return target.strip().lower().rstrip(".")


class RdapCollector(BaseCollector):
    name = "rdap"
    description = "Query public ICANN RDAP for domain or IP registration metadata."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        host = _extract_host(target)
        res = CollectorResult(collector=self.name, target=host)
        try:
            try:
                ipaddress.ip_address(host)
                url = f"https://rdap.org/ip/{host}"
                kind = "ip_address"
            except ValueError:
                url = f"https://rdap.org/domain/{host}"
                kind = "domain"

            resp = http.get(url)
            if resp.status_code != 200:
                res.status = "empty"
                res.error = f"RDAP returned HTTP {resp.status_code}"
                return res

            data = resp.json()
            res.sources.append(
                SourceRecord(
                    url=str(resp.url),
                    title=f"RDAP record for {host}",
                    source_type="registry",
                    snippet=f"RDAP {kind} record for {host}",
                )
            )
            res.entities.append(EntityRecord(name=host, entity_type=kind))

            events = {e.get("eventAction"): e.get("eventDate", "") for e in data.get("events", [])}
            statuses = data.get("status", [])
            nameservers = [ns.get("ldhName", "").lower() for ns in data.get("nameservers", []) if ns.get("ldhName")]

            summary_parts = []
            if events.get("registration"):
                summary_parts.append(f"registered {events['registration']}")
            if events.get("expiration"):
                summary_parts.append(f"expires {events['expiration']}")
            if statuses:
                summary_parts.append(f"status: {', '.join(statuses[:4])}")
            if nameservers:
                summary_parts.append(f"nameservers: {', '.join(nameservers[:4])}")

            if summary_parts:
                res.findings.append(
                    FindingRecord(
                        category="Technical Findings",
                        claim=f"RDAP registration for {host}: {'; '.join(summary_parts)}.",
                        confidence="VERY HIGH",
                        source_urls=[str(resp.url)],
                        rationale="Authoritative RDAP registry response.",
                        published_date=events.get("last changed", ""),
                    )
                )

            for ns in nameservers[:6]:
                res.entities.append(EntityRecord(name=ns, entity_type="nameserver"))
                res.relationships.append(
                    RelationshipRecord(
                        source_entity=host,
                        relation="uses_nameserver",
                        target_entity=ns,
                        evidence_url=str(resp.url),
                        confidence="VERY HIGH",
                    )
                )

            res.raw_summary = {"events": events, "status": statuses, "nameservers": nameservers}
            return res
        except Exception as exc:
            res.status = "error"
            res.error = str(exc)
            return res


class DnsCollector(BaseCollector):
    name = "dns"
    description = "Query public DNS records (A, AAAA, MX, TXT, NS) via local dig."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        host = _extract_host(target)
        res = CollectorResult(collector=self.name, target=host)
        dig_bin = shutil.which("dig")
        if not dig_bin:
            res.status = "skipped"
            res.error = "dig binary not available on PATH"
            return res

        records: dict[str, list[str]] = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                proc = subprocess.run(
                    [dig_bin, "+short", host, rtype],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    check=False,
                )
                lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
                if lines:
                    records[rtype] = lines[:10]
            except Exception:
                continue

        if not records:
            res.status = "empty"
            return res

        dns_ref = f"dns://{host}"
        res.sources.append(
            SourceRecord(
                url=dns_ref,
                title=f"Public DNS records for {host}",
                source_type="dns",
                snippet=str(records)[:400],
            )
        )
        res.findings.append(
            FindingRecord(
                category="Technical Findings",
                claim=f"Public DNS records for {host}: "
                + "; ".join(f"{k}={', '.join(v[:3])}" for k, v in records.items()),
                confidence="VERY HIGH",
                source_urls=[dns_ref],
                rationale="Direct public DNS resolution via dig.",
            )
        )
        for ip in records.get("A", [])[:3]:
            res.entities.append(EntityRecord(name=ip, entity_type="ip_address"))
            res.relationships.append(
                RelationshipRecord(
                    source_entity=host,
                    relation="resolves_to",
                    target_entity=ip,
                    evidence_url=dns_ref,
                    confidence="VERY HIGH",
                )
            )
        res.raw_summary = records
        return res


class CrtShCollector(BaseCollector):
    name = "crtsh"
    description = "Query crt.sh Certificate Transparency logs for subdomains."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        host = _extract_host(target)
        res = CollectorResult(collector=self.name, target=host)
        url = f"https://crt.sh/?q=%25.{host}&output=json"
        try:
            resp = http.get(url)
            if resp.status_code != 200:
                res.status = "empty"
                res.error = f"crt.sh returned HTTP {resp.status_code}"
                return res
            data = resp.json()
            subdomains: set[str] = set()
            for entry in data[:300]:
                name_val = entry.get("name_value", "")
                for line in name_val.splitlines():
                    cleaned = line.strip().lower().lstrip("*.")
                    if cleaned.endswith(host) and cleaned != host:
                        subdomains.add(cleaned)

            sorted_subs = sorted(subdomains)[:40]
            if not sorted_subs:
                res.status = "empty"
                return res

            res.sources.append(
                SourceRecord(
                    url=url,
                    title=f"crt.sh Certificate Transparency logs for {host}",
                    source_type="ct_logs",
                    snippet=f"Discovered {len(subdomains)} unique subdomains.",
                )
            )
            res.findings.append(
                FindingRecord(
                    category="Technical Findings",
                    claim=f"Certificate Transparency (crt.sh) lists {len(subdomains)} subdomains for {host}, including: {', '.join(sorted_subs[:10])}.",
                    confidence="HIGH",
                    source_urls=[url],
                    rationale="Public SSL/TLS Certificate Transparency log entries.",
                )
            )
            for sub in sorted_subs[:10]:
                res.entities.append(EntityRecord(name=sub, entity_type="subdomain"))
                res.relationships.append(
                    RelationshipRecord(
                        source_entity=sub,
                        relation="subdomain_of",
                        target_entity=host,
                        evidence_url=url,
                        confidence="HIGH",
                    )
                )
            res.raw_summary = {"total_unique": len(subdomains), "sample": sorted_subs[:20]}
            return res
        except Exception as exc:
            res.status = "error"
            res.error = str(exc)
            return res


class WaybackCollector(BaseCollector):
    name = "wayback"
    description = "Query Internet Archive Wayback Machine CDX API for historical snapshots."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        host = _extract_host(target)
        res = CollectorResult(collector=self.name, target=host)
        url = (
            f"https://web.archive.org/cdx/search/cdx?url={host}"
            "&output=json&fl=timestamp,original,statuscode,mimetype&limit=10&collapse=timestamp:6"
        )
        try:
            resp = http.get(url)
            if resp.status_code != 200:
                res.status = "empty"
                res.error = f"Wayback CDX returned HTTP {resp.status_code}"
                return res
            rows = resp.json()
            if len(rows) <= 1:
                res.status = "empty"
                return res
            entries = rows[1:]
            first_ts = entries[0][0]
            last_ts = entries[-1][0]
            archive_url = f"https://web.archive.org/web/*/{host}"
            res.sources.append(
                SourceRecord(
                    url=archive_url,
                    title=f"Wayback Machine archive history for {host}",
                    source_type="archive",
                    published_date=f"{first_ts[:4]}-{first_ts[4:6]}-{first_ts[6:8]}",
                    snippet=f"Archived snapshots sampled from {first_ts[:8]} to {last_ts[:8]}",
                )
            )
            res.findings.append(
                FindingRecord(
                    category="Timeline of Events",
                    claim=f"Wayback Machine holds archived snapshots of {host} spanning at least {first_ts[:4]}-{first_ts[4:6]}-{first_ts[6:8]} through {last_ts[:4]}-{last_ts[4:6]}-{last_ts[6:8]}.",
                    confidence="HIGH",
                    source_urls=[archive_url],
                    rationale="Internet Archive CDX index.",
                    published_date=f"{first_ts[:4]}-{first_ts[4:6]}-{first_ts[6:8]}",
                )
            )
            res.leads.append(LeadRecord(target=f"https://{host}", collector="web_fetch", priority=3))
            res.raw_summary = {"sample_count": len(entries), "first_ts": first_ts, "last_ts": last_ts}
            return res
        except Exception as exc:
            res.status = "error"
            res.error = str(exc)
            return res
