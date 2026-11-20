"""Public community and academic collectors (Hacker News Algolia, Reddit JSON, arXiv, Crossref)."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ..http_client import PoliteHTTPClient
from .base import BaseCollector, CollectorResult, FindingRecord, SourceRecord


class HackerNewsCollector(BaseCollector):
    name = "hn"
    description = "Search Hacker News via the public Algolia API."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        res = CollectorResult(collector=self.name, target=target)
        try:
            resp = http.get(
                "https://hn.algolia.com/api/v1/search",
                params={"query": target, "hitsPerPage": "5"},
            )
            if resp.status_code != 200:
                res.status = "empty"
                return res
            hits = resp.json().get("hits", [])
            if not hits:
                res.status = "empty"
                return res
            urls = []
            for h in hits[:5]:
                hn_url = f"https://news.ycombinator.com/item?id={h.get('objectID')}"
                urls.append(hn_url)
                res.sources.append(
                    SourceRecord(
                        url=hn_url,
                        title=h.get("title") or h.get("story_title") or f"HN item {h.get('objectID')}",
                        source_type="forum",
                        published_date=(h.get("created_at") or "")[:10],
                        snippet=f"Points: {h.get('points', 0)}, Comments: {h.get('num_comments', 0)}",
                    )
                )
            res.findings.append(
                FindingRecord(
                    category="Key Findings",
                    claim=f"Hacker News contains {len(hits)} top discussions mentioning '{target}', including '{hits[0].get('title') or hits[0].get('story_title')}'.",
                    confidence="MODERATE",
                    source_urls=urls[:3],
                    rationale="Public Hacker News community discussions (treat claims in comments as unverified unless corroborated).",
                )
            )
            return res
        except Exception as exc:
            res.status = "error"
            res.error = str(exc)
            return res


class RedditCollector(BaseCollector):
    name = "reddit"
    description = "Search public Reddit posts via public JSON endpoint."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        res = CollectorResult(collector=self.name, target=target)
        try:
            resp = http.get(
                "https://www.reddit.com/search.json",
                params={"q": target, "limit": "5", "sort": "relevance"},
            )
            if resp.status_code != 200:
                res.status = "empty"
                res.error = f"Reddit returned HTTP {resp.status_code}"
                return res
            children = resp.json().get("data", {}).get("children", [])
            if not children:
                res.status = "empty"
                return res
            urls = []
            for ch in children[:5]:
                post = ch.get("data", {})
                permalink = f"https://www.reddit.com{post.get('permalink', '')}"
                urls.append(permalink)
                res.sources.append(
                    SourceRecord(
                        url=permalink,
                        title=f"r/{post.get('subreddit', '')}: {post.get('title', '')}",
                        source_type="forum",
                        snippet=(post.get("selftext") or "")[:300],
                    )
                )
            res.findings.append(
                FindingRecord(
                    category="Key Findings",
                    claim=f"Public Reddit search returned {len(children)} relevant threads for '{target}'.",
                    confidence="MODERATE",
                    source_urls=urls[:3],
                    rationale="Public Reddit posts (user-generated content; corroborate independently).",
                )
            )
            return res
        except Exception as exc:
            res.status = "error"
            res.error = str(exc)
            return res


class ArxivCollector(BaseCollector):
    name = "arxiv"
    description = "Search arXiv academic preprints via public Atom API."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        res = CollectorResult(collector=self.name, target=target)
        try:
            resp = http.get(
                "https://export.arxiv.org/api/query",
                params={"search_query": f"all:{target}", "start": "0", "max_results": "5"},
            )
            if resp.status_code != 200:
                res.status = "empty"
                return res
            root = ET.fromstring(resp.text)
            ns = {"atom": "http://www.w3.org/2005/Atom"}
            entries = root.findall("atom:entry", ns)
            if not entries:
                res.status = "empty"
                return res
            urls = []
            for entry in entries[:5]:
                title = (entry.findtext("atom:title", default="", namespaces=ns) or "").strip().replace("\n", " ")
                link = (entry.findtext("atom:id", default="", namespaces=ns) or "").strip()
                pub = (entry.findtext("atom:published", default="", namespaces=ns) or "")[:10]
                summary = (entry.findtext("atom:summary", default="", namespaces=ns) or "").strip().replace("\n", " ")
                if link:
                    urls.append(link)
                    res.sources.append(
                        SourceRecord(
                            url=link,
                            title=f"arXiv: {title}",
                            source_type="academic",
                            published_date=pub,
                            snippet=summary[:300],
                        )
                    )
            res.findings.append(
                FindingRecord(
                    category="Key Findings",
                    claim=f"arXiv indexes {len(entries)} recent/relevant preprints matching '{target}'.",
                    confidence="HIGH",
                    source_urls=urls[:3],
                    rationale="Public arXiv academic repository.",
                )
            )
            return res
        except Exception as exc:
            res.status = "error"
            res.error = str(exc)
            return res


class CrossrefCollector(BaseCollector):
    name = "crossref"
    description = "Search Crossref academic publications metadata."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        res = CollectorResult(collector=self.name, target=target)
        try:
            resp = http.get(
                "https://api.crossref.org/works",
                params={"query": target, "rows": "5"},
            )
            if resp.status_code != 200:
                res.status = "empty"
                return res
            items = resp.json().get("message", {}).get("items", [])
            if not items:
                res.status = "empty"
                return res
            urls = []
            for it in items[:5]:
                url = it.get("URL", "")
                title = (it.get("title") or ["Untitled"])[0]
                if url:
                    urls.append(url)
                    res.sources.append(
                        SourceRecord(
                            url=url,
                            title=f"Crossref: {title}",
                            source_type="academic",
                            snippet=f"Publisher: {it.get('publisher', 'unknown')}",
                        )
                    )
            res.findings.append(
                FindingRecord(
                    category="Key Findings",
                    claim=f"Crossref indexes {len(items)} scholarly works matching '{target}'.",
                    confidence="HIGH",
                    source_urls=urls[:3],
                    rationale="Public Crossref DOI metadata registry.",
                )
            )
            return res
        except Exception as exc:
            res.status = "error"
            res.error = str(exc)
            return res
