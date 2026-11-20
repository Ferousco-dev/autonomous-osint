"""GitHub and GitLab public API collectors (no API key required; optional token via env)."""

from __future__ import annotations

import os

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


class GitHubCollector(BaseCollector):
    name = "github"
    description = "Query public GitHub REST API for users, orgs, and repositories."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        res = CollectorResult(collector=self.name, target=target)
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            # Direct repo lookup if owner/repo
            if "/" in target and " " not in target:
                url = f"https://api.github.com/repos/{target.strip('/')}"
                resp = http.get(url, headers=headers)
                if resp.status_code == 200:
                    repo = resp.json()
                    html_url = repo["html_url"]
                    res.sources.append(
                        SourceRecord(
                            url=html_url,
                            title=f"GitHub Repo: {repo['full_name']}",
                            source_type="code_repo",
                            published_date=repo.get("created_at", "")[:10],
                            snippet=repo.get("description") or "",
                        )
                    )
                    res.entities.append(
                        EntityRecord(
                            name=repo["full_name"],
                            entity_type="github_repo",
                            attributes={
                                "stars": repo.get("stargazers_count"),
                                "language": repo.get("language"),
                                "homepage": repo.get("homepage"),
                            },
                        )
                    )
                    res.findings.append(
                        FindingRecord(
                            category="Technical Findings",
                            claim=(
                                f"GitHub repository {repo['full_name']} ({repo.get('language') or 'unknown language'}, "
                                f"{repo.get('stargazers_count', 0)} stars): {repo.get('description') or 'No description'}."
                            ),
                            confidence="VERY HIGH",
                            source_urls=[html_url],
                            rationale="Direct GitHub REST API metadata.",
                            published_date=repo.get("created_at", "")[:10],
                        )
                    )
                    if repo.get("homepage"):
                        res.leads.append(LeadRecord(target=repo["homepage"], collector="web_fetch", priority=3))
                    return res

            # Search repositories
            search_url = "https://api.github.com/search/repositories"
            resp = http.get(search_url, params={"q": target, "per_page": "5", "sort": "stars"}, headers=headers)
            if resp.status_code != 200:
                res.status = "empty" if resp.status_code == 404 else "error"
                res.error = f"GitHub API returned HTTP {resp.status_code}"
                return res

            items = resp.json().get("items", [])
            if not items:
                res.status = "empty"
                return res

            for repo in items[:5]:
                html_url = repo["html_url"]
                owner = repo.get("owner", {}).get("login", "")
                res.sources.append(
                    SourceRecord(
                        url=html_url,
                        title=f"GitHub: {repo['full_name']}",
                        source_type="code_repo",
                        published_date=repo.get("created_at", "")[:10],
                        snippet=repo.get("description") or "",
                    )
                )
                res.entities.append(EntityRecord(name=repo["full_name"], entity_type="github_repo"))
                if owner:
                    res.relationships.append(
                        RelationshipRecord(
                            source_entity=owner,
                            relation="owns_repository",
                            target_entity=repo["full_name"],
                            evidence_url=html_url,
                            confidence="VERY HIGH",
                        )
                    )

            top = items[0]
            res.findings.append(
                FindingRecord(
                    category="Key Findings",
                    claim=f"GitHub search for '{target}' returned {len(items)} top repositories; highest-starred is {top['full_name']} ({top.get('stargazers_count', 0)} stars).",
                    confidence="HIGH",
                    source_urls=[r["html_url"] for r in items[:3]],
                    rationale="Public GitHub repository search.",
                )
            )
            return res
        except Exception as exc:
            res.status = "error"
            res.error = str(exc)
            return res


class GitLabCollector(BaseCollector):
    name = "gitlab"
    description = "Query public GitLab projects API."

    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        res = CollectorResult(collector=self.name, target=target)
        try:
            resp = http.get(
                "https://gitlab.com/api/v4/projects",
                params={"search": target, "per_page": "5", "order_by": "star_count"},
            )
            if resp.status_code != 200:
                res.status = "empty"
                res.error = f"GitLab API returned HTTP {resp.status_code}"
                return res
            items = resp.json()
            if not items:
                res.status = "empty"
                return res
            for proj in items[:5]:
                url = proj.get("web_url", "")
                name = proj.get("path_with_namespace", proj.get("name", ""))
                res.sources.append(
                    SourceRecord(
                        url=url,
                        title=f"GitLab: {name}",
                        source_type="code_repo",
                        published_date=(proj.get("created_at") or "")[:10],
                        snippet=proj.get("description") or "",
                    )
                )
                res.entities.append(EntityRecord(name=name, entity_type="gitlab_repo"))
            res.findings.append(
                FindingRecord(
                    category="Technical Findings",
                    claim=f"GitLab public search for '{target}' found {len(items)} matching projects.",
                    confidence="HIGH",
                    source_urls=[p.get("web_url", "") for p in items[:3] if p.get("web_url")],
                    rationale="Public GitLab REST API.",
                )
            )
            return res
        except Exception as exc:
            res.status = "error"
            res.error = str(exc)
            return res
