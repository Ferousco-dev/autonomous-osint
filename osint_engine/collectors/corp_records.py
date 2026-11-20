"""Public corporate, registry, and encyclopedia collectors (Wikipedia, SEC EDGAR, OpenCorporates)."""

from __future__ import annotations

from urllib.parse import quote

from ..http_client import PoliteHTTPClient
from .base import (
    BaseCollector,
    CollectorResult,
    EntityRecord,
    FindingRecord,
    SourceRecord,
)


class WikipediaCollector(BaseCollector):
    name = "wiki"
    description = "Query Wikipedia REST summary & search API for background and disambiguation."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        res = CollectorResult(collector=self.name, target=target)
        try:
            search_resp = http.get(
                "https://en.wikipedia.org/w/api.php",
                params={
                    "action": "opensearch",
                    "search": target,
                    "limit": "3",
                    "namespace": "0",
                    "format": "json",
                },
            )
            if search_resp.status_code != 200:
                res.status = "empty"
                return res
            data = search_resp.json()
            titles = data[1] if len(data) > 1 else []
            urls = data[3] if len(data) > 3 else []
            if not titles:
                res.status = "empty"
                return res

            top_title = titles[0]
            summary_resp = http.get(
                f"https://en.wikipedia.org/api/rest_v1/page/summary/{quote(top_title.replace(' ', '_'))}"
            )
            extract = ""
            page_url = urls[0] if urls else f"https://en.wikipedia.org/wiki/{quote(top_title.replace(' ', '_'))}"
            if summary_resp.status_code == 200:
                sdata = summary_resp.json()
                extract = sdata.get("extract", "")
                page_url = sdata.get("content_urls", {}).get("desktop", {}).get("page", page_url)

            res.sources.append(
                SourceRecord(
                    url=page_url,
                    title=f"Wikipedia: {top_title}",
                    source_type="encyclopedia",
                    snippet=extract[:400],
                )
            )
            res.entities.append(EntityRecord(name=top_title, entity_type="wikipedia_subject"))
            if extract:
                res.findings.append(
                    FindingRecord(
                        category="Background",
                        claim=extract[:600],
                        confidence="HIGH",
                        source_urls=[page_url],
                        rationale="Wikipedia encyclopedic summary (corroborate key facts with primary sources).",
                    )
                )
            return res
        except Exception as exc:
            res.status = "error"
            res.error = str(exc)
            return res


class SecEdgarCollector(BaseCollector):
    name = "edgar"
    description = "Query U.S. SEC EDGAR public company ticker/CIK registry."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        res = CollectorResult(collector=self.name, target=target)
        try:
            resp = http.get(
                "https://www.sec.gov/files/company_tickers.json",
                headers={"User-Agent": "AutonomousOSINTResearch/0.1 research@example.com"},
            )
            if resp.status_code != 200:
                res.status = "empty"
                res.error = f"SEC EDGAR returned HTTP {resp.status_code}"
                return res

            needle = target.lower().strip()
            matches = []
            for entry in resp.json().values():
                title = str(entry.get("title", ""))
                ticker = str(entry.get("ticker", ""))
                if needle in title.lower() or needle == ticker.lower():
                    matches.append(entry)
                if len(matches) >= 5:
                    break

            if not matches:
                res.status = "empty"
                return res

            for m in matches:
                cik = str(m["cik_str"]).zfill(10)
                edgar_url = f"https://www.sec.gov/edgar/browse/?CIK={cik}"
                res.sources.append(
                    SourceRecord(
                        url=edgar_url,
                        title=f"SEC EDGAR: {m['title']} ({m['ticker']})",
                        source_type="government_registry",
                        snippet=f"CIK {cik}, Ticker {m['ticker']}",
                    )
                )
                res.entities.append(
                    EntityRecord(
                        name=m["title"],
                        entity_type="public_company",
                        attributes={"cik": cik, "ticker": m["ticker"]},
                    )
                )
            top = matches[0]
            cik = str(top["cik_str"]).zfill(10)
            res.findings.append(
                FindingRecord(
                    category="Key Findings",
                    claim=f"SEC EDGAR lists '{top['title']}' (Ticker: {top['ticker']}, CIK: {cik}).",
                    confidence="VERY HIGH",
                    source_urls=[f"https://www.sec.gov/edgar/browse/?CIK={cik}"],
                    rationale="Official U.S. SEC EDGAR public registry.",
                )
            )
            return res
        except Exception as exc:
            res.status = "error"
            res.error = str(exc)
            return res


class OpenCorporatesCollector(BaseCollector):
    name = "opencorporates"
    description = "Query OpenCorporates public company search API."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        res = CollectorResult(collector=self.name, target=target)
        try:
            resp = http.get(
                "https://api.opencorporates.com/v0.4/companies/search",
                params={"q": target, "per_page": "5"},
            )
            if resp.status_code != 200:
                res.status = "empty"
                res.error = f"OpenCorporates returned HTTP {resp.status_code}"
                return res
            companies = resp.json().get("results", {}).get("companies", [])
            if not companies:
                res.status = "empty"
                return res
            for item in companies[:5]:
                c = item.get("company", {})
                url = c.get("opencorporates_url", "")
                name = c.get("name", "")
                jur = c.get("jurisdiction_code", "")
                if url:
                    res.sources.append(
                        SourceRecord(
                            url=url,
                            title=f"OpenCorporates: {name} ({jur})",
                            source_type="company_registry",
                            published_date=c.get("incorporation_date") or "",
                            snippet=f"Status: {c.get('current_status') or 'unknown'}; Jurisdiction: {jur}",
                        )
                    )
                res.entities.append(
                    EntityRecord(
                        name=name,
                        entity_type="registered_company",
                        attributes={"jurisdiction": jur, "status": c.get("current_status")},
                    )
                )
            res.findings.append(
                FindingRecord(
                    category="Key Findings",
                    claim=f"OpenCorporates returned {len(companies)} corporate registry matches for '{target}'.",
                    confidence="HIGH",
                    source_urls=[
                        item["company"]["opencorporates_url"]
                        for item in companies[:3]
                        if item.get("company", {}).get("opencorporates_url")
                    ],
                    rationale="Public OpenCorporates company registry index.",
                )
            )
            return res
        except Exception as exc:
            res.status = "error"
            res.error = str(exc)
            return res
