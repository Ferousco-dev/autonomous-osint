"""Modular OSINT collectors."""

from .base import BaseCollector, CollectorResult
from .domain_net import CrtShCollector, DnsCollector, RdapCollector, WaybackCollector
from .code_repos import GitHubCollector, GitLabCollector
from .corp_records import OpenCorporatesCollector, SecEdgarCollector, WikipediaCollector
from .community_academic import ArxivCollector, CrossrefCollector, HackerNewsCollector, RedditCollector
from .web_fetch import WebFetchCollector
from .username_cli import UsernameCliCollector

COLLECTOR_REGISTRY: dict[str, type[BaseCollector]] = {
    "rdap": RdapCollector,
    "dns": DnsCollector,
    "crtsh": CrtShCollector,
    "wayback": WaybackCollector,
    "github": GitHubCollector,
    "gitlab": GitLabCollector,
    "edgar": SecEdgarCollector,
    "opencorporates": OpenCorporatesCollector,
    "wiki": WikipediaCollector,
    "hn": HackerNewsCollector,
    "reddit": RedditCollector,
    "arxiv": ArxivCollector,
    "crossref": CrossrefCollector,
    "web_fetch": WebFetchCollector,
    "username_cli": UsernameCliCollector,
}

__all__ = ["BaseCollector", "CollectorResult", "COLLECTOR_REGISTRY"]
