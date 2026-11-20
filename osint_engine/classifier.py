"""Universal entity classifier for arbitrary OSINT inputs."""

from __future__ import annotations

import ipaddress
import re
from enum import Enum
from pydantic import BaseModel, Field


class EntityType(str, Enum):
    DOMAIN = "domain"
    URL = "url"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    GITHUB_REPO = "github_repo"
    USERNAME = "username"
    ORGANIZATION = "organization"
    PERSON = "person"
    TECHNOLOGY = "technology"
    LOCATION = "location"
    PHRASE_OR_EVENT = "phrase_or_event"
    UNKNOWN = "unknown"


class ClassificationResult(BaseModel):
    raw_input: str
    normalized: str
    primary_type: EntityType
    secondary_types: list[EntityType] = Field(default_factory=list)
    recommended_collectors: list[str] = Field(default_factory=list)
    initial_queries: list[str] = Field(default_factory=list)
    notes: str = ""


_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_GH_REPO_RE = re.compile(
    r"^(?:https?://github\.com/)?([a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+)(?:\.git)?/?$"
)
_HANDLE_RE = re.compile(r"^@[a-zA-Z0-9_.\-]{2,39}$")
_ORG_SUFFIXES = (
    "inc",
    "inc.",
    "llc",
    "ltd",
    "ltd.",
    "corp",
    "corp.",
    "corporation",
    "foundation",
    "labs",
    "technologies",
    "systems",
    "group",
    "holdings",
    "gmbh",
    "plc",
    "sa",
    "ag",
    "org",
    "institute",
    "university",
)


def classify_input(raw: str) -> ClassificationResult:
    """Classify any input (even a single word) into an OSINT research strategy."""
    text = raw.strip()
    if not text:
        return ClassificationResult(
            raw_input=raw,
            normalized="",
            primary_type=EntityType.UNKNOWN,
            notes="Empty input provided.",
        )

    # 1. IP Address
    try:
        ip = ipaddress.ip_address(text)
        return ClassificationResult(
            raw_input=raw,
            normalized=str(ip),
            primary_type=EntityType.IP_ADDRESS,
            recommended_collectors=["rdap", "dns"],
            initial_queries=[
                f'"{ip}"',
                f'"{ip}" ASN OR owner OR abuse',
            ],
            notes="Exact IPv4/IPv6 address detected.",
        )
    except ValueError:
        pass

    # 2. Email Address
    if _EMAIL_RE.match(text):
        local, domain = text.split("@", 1)
        return ClassificationResult(
            raw_input=raw,
            normalized=text.lower(),
            primary_type=EntityType.EMAIL,
            secondary_types=[EntityType.DOMAIN, EntityType.USERNAME],
            recommended_collectors=["rdap", "dns", "github"],
            initial_queries=[
                f'"{text.lower()}"',
                f'"{local}" "{domain}"',
            ],
            notes=f"Email detected; can pivot on domain '{domain}' and local-part '{local}' (public sources only).",
        )

    # 3. GitHub Repository (URL or owner/repo)
    gh_match = _GH_REPO_RE.match(text)
    if gh_match and ("github.com" in text.lower() or "/" in text):
        repo_slug = gh_match.group(1).rstrip("/")
        if not text.lower().startswith("http") or "github.com" in text.lower():
            return ClassificationResult(
                raw_input=raw,
                normalized=repo_slug,
                primary_type=EntityType.GITHUB_REPO,
                secondary_types=[EntityType.TECHNOLOGY],
                recommended_collectors=["github", "hn", "reddit", "arxiv"],
                initial_queries=[
                    f'"{repo_slug}"',
                    f'"{repo_slug}" security OR vulnerability OR release',
                ],
                notes="GitHub repository slug detected.",
            )

    # 4. URL
    if _URL_RE.match(text):
        host = re.sub(r"^https?://", "", text, flags=re.IGNORECASE).split("/", 1)[0].split(":", 1)[0]
        return ClassificationResult(
            raw_input=raw,
            normalized=text,
            primary_type=EntityType.URL,
            secondary_types=[EntityType.DOMAIN],
            recommended_collectors=["web_fetch", "wayback", "rdap", "dns", "crtsh"],
            initial_queries=[
                f'"{text}"',
                f'site:{host}',
            ],
            notes=f"Full URL detected; host is '{host}'.",
        )

    # 5. Domain
    if _DOMAIN_RE.match(text) and " " not in text:
        domain = text.lower().rstrip(".")
        return ClassificationResult(
            raw_input=raw,
            normalized=domain,
            primary_type=EntityType.DOMAIN,
            secondary_types=[EntityType.ORGANIZATION],
            recommended_collectors=["rdap", "dns", "crtsh", "wayback", "web_fetch", "github"],
            initial_queries=[
                f'site:{domain}',
                f'"{domain}"',
                f'"{domain}" founder OR leadership OR security',
            ],
            notes="Domain name detected.",
        )

    # 6. Explicit @handle
    if _HANDLE_RE.match(text):
        handle = text[1:]
        return ClassificationResult(
            raw_input=raw,
            normalized=handle,
            primary_type=EntityType.USERNAME,
            recommended_collectors=["github", "hn", "reddit", "username_cli"],
            initial_queries=[
                f'"{handle}"',
                f'"{text}"',
            ],
            notes="Explicit social/platform handle detected.",
        )

    tokens = text.split()
    lower_tokens = [t.lower().strip(",.") for t in tokens]

    # 7. Organization indicators
    if any(tok in _ORG_SUFFIXES for tok in lower_tokens):
        return ClassificationResult(
            raw_input=raw,
            normalized=text,
            primary_type=EntityType.ORGANIZATION,
            recommended_collectors=["wiki", "edgar", "opencorporates", "github", "hn", "reddit"],
            initial_queries=[
                f'"{text}"',
                f'"{text}" official website',
                f'"{text}" founders OR executives OR headquarters',
                f'"{text}" news OR controversy OR security',
            ],
            notes="Corporate/organization suffix detected.",
        )

    # 8. Single-word ambiguous input (could be company, product, username, tech, or person)
    if len(tokens) == 1:
        return ClassificationResult(
            raw_input=raw,
            normalized=text,
            primary_type=EntityType.ORGANIZATION,
            secondary_types=[
                EntityType.TECHNOLOGY,
                EntityType.USERNAME,
                EntityType.PERSON,
            ],
            recommended_collectors=["wiki", "github", "hn", "reddit", "opencorporates", "arxiv"],
            initial_queries=[
                f'"{text}"',
                f'"{text}" official website OR github',
                f'"{text}" company OR project OR software',
            ],
            notes=(
                "Single-word input is inherently polysemous; starting with broad multi-source "
                "discovery (Wikipedia, GitHub, HN, Reddit, OpenCorporates, Web) to disambiguate."
            ),
        )

    # 9. Multi-word capitalized (likely Person, Organization, or Location)
    if 2 <= len(tokens) <= 3 and all(t[0].isupper() for t in tokens if t[0].isalpha()):
        return ClassificationResult(
            raw_input=raw,
            normalized=text,
            primary_type=EntityType.PERSON,
            secondary_types=[EntityType.ORGANIZATION, EntityType.LOCATION],
            recommended_collectors=["wiki", "github", "hn", "reddit", "arxiv", "opencorporates"],
            initial_queries=[
                f'"{text}"',
                f'"{text}" biography OR profile OR organization',
                f'"{text}" github OR publications OR interviews',
            ],
            notes="Multi-word proper noun; could be a person, organization, or location. Apply privacy guardrails if private individual.",
        )

    # 10. General phrase, event, or technology
    return ClassificationResult(
        raw_input=raw,
        normalized=text,
        primary_type=EntityType.PHRASE_OR_EVENT,
        secondary_types=[EntityType.TECHNOLOGY],
        recommended_collectors=["wiki", "hn", "reddit", "arxiv"],
        initial_queries=[
            f'"{text}"',
            f'"{text}" analysis OR report OR timeline',
        ],
        notes="Phrase, event, or technology topic detected.",
    )
