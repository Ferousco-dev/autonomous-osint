"""Base interface for all pluggable OSINT collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel, Field

from ..http_client import PoliteHTTPClient


class SourceRecord(BaseModel):
    url: str
    title: str = ""
    source_type: str = "web"
    published_date: str = ""
    snippet: str = ""


class EntityRecord(BaseModel):
    name: str
    entity_type: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class RelationshipRecord(BaseModel):
    source_entity: str
    relation: str
    target_entity: str
    evidence_url: str = ""
    confidence: str = "MODERATE"


class FindingRecord(BaseModel):
    category: str
    claim: str
    confidence: str = "MODERATE"
    source_urls: list[str] = Field(default_factory=list)
    rationale: str = ""
    is_fact: bool = True
    published_date: str = ""


class LeadRecord(BaseModel):
    target: str
    collector: str
    priority: int = 5


class CollectorResult(BaseModel):
    collector: str
    target: str
    status: str = "ok"  # ok | empty | error | skipped
    error: str = ""
    sources: list[SourceRecord] = Field(default_factory=list)
    entities: list[EntityRecord] = Field(default_factory=list)
    relationships: list[RelationshipRecord] = Field(default_factory=list)
    findings: list[FindingRecord] = Field(default_factory=list)
    leads: list[LeadRecord] = Field(default_factory=list)
    raw_summary: dict[str, Any] = Field(default_factory=dict)


class BaseCollector(ABC):
    name: str = "base"
    description: str = ""
    requires_api_key: bool = False

    @abstractmethod
    def run(self, target: str, http: PoliteHTTPClient) -> CollectorResult:
        """Execute passive collection against a target."""
        raise NotImplementedError
