"""Respectful, robots.txt-aware public web page fetcher and metadata extractor."""

from __future__ import annotations

from bs4 import BeautifulSoup

from ..http_client import PoliteHTTPClient
from .base import BaseCollector, CollectorResult, FindingRecord, SourceRecord


class WebFetchCollector(BaseCollector):
    name = "web_fetch"
    description = "Fetch a public webpage respecting robots.txt and extract title, description, and text."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        res = CollectorResult(collector=self.name, target=url)
        try:
            resp = http.get(url, check_robots=True)
            if resp.status_code != 200:
                res.status = "empty"
                res.error = f"HTTP {resp.status_code}"
                return res

            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()

            title = (soup.title.string or "").strip() if soup.title and soup.title.string else url
            meta_desc = ""
            meta = soup.find("meta", attrs={"name": "description"})
            if meta and meta.get("content"):
                meta_desc = str(meta["content"]).strip()

            text = " ".join(soup.get_text(" ", strip=True).split())[:800]
            snippet = meta_desc or text[:350]

            res.sources.append(
                SourceRecord(
                    url=str(resp.url),
                    title=title,
                    source_type="official_website",
                    snippet=snippet,
                )
            )
            res.findings.append(
                FindingRecord(
                    category="Background",
                    claim=f"Public page '{title}' ({resp.url}): {snippet}",
                    confidence="HIGH",
                    source_urls=[str(resp.url)],
                    rationale="Direct public webpage fetch (robots.txt respected).",
                )
            )
            res.raw_summary = {"title": title, "final_url": str(resp.url), "description": meta_desc}
            return res
        except PermissionError as exc:
            res.status = "skipped"
            res.error = str(exc)
            return res
        except Exception as exc:
            res.status = "error"
            res.error = str(exc)
            return res
