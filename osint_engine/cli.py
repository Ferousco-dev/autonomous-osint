"""CLI entrypoint for the Autonomous OSINT Research Engine."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .classifier import classify_input
from .collectors import COLLECTOR_REGISTRY
from .http_client import PoliteHTTPClient
from .report import generate_report
from .state import SessionStore, make_session_id
from .verifier import normalize_confidence

DEFAULT_SESSIONS_DIR = Path("sessions")


def _ingest_collector_result(store: SessionStore, res: object, depth: int) -> None:
    from .collectors.base import CollectorResult

    assert isinstance(res, CollectorResult)
    store.record_search(res.collector, res.target, res.status, len(res.sources))
    for s in res.sources:
        store.add_source(
            s.url,
            title=s.title,
            source_type=s.source_type,
            published_date=s.published_date,
            collector=res.collector,
            snippet=s.snippet,
        )
    for e in res.entities:
        store.add_entity(e.name, e.entity_type, e.attributes)
    for r in res.relationships:
        store.add_relationship(
            r.source_entity,
            r.relation,
            r.target_entity,
            evidence_url=r.evidence_url,
            confidence=normalize_confidence(r.confidence),
        )
    for f in res.findings:
        store.add_finding(
            category=f.category,
            claim=f.claim,
            confidence=normalize_confidence(f.confidence),
            source_urls=f.source_urls,
            rationale=f.rationale,
            is_fact=f.is_fact,
            published_date=f.published_date,
        )
    for ld in res.leads:
        store.add_lead(ld.target, ld.collector, depth=depth + 1, priority=ld.priority)


def cmd_init(args: argparse.Namespace) -> None:
    classification = classify_input(args.subject)
    session_id = args.session_id or make_session_id(args.subject)
    session_dir = Path(args.sessions_dir) / session_id
    store = SessionStore(session_dir)
    try:
        store.set_meta("session_id", session_id)
        store.set_meta("subject", args.subject)
        store.set_meta("classification", classification.model_dump())
        store.set_meta("max_depth", args.max_depth)
        store.set_meta("max_searches", args.max_searches)
        store.add_entity(classification.normalized, classification.primary_type.value)
        for idx, col in enumerate(classification.recommended_collectors):
            store.add_lead(classification.normalized, col, depth=1, priority=idx + 1)
        store.export_snapshot()
        print(
            json.dumps(
                {
                    "session_id": session_id,
                    "session_dir": str(session_dir.resolve()),
                    "classification": classification.model_dump(),
                },
                indent=2,
            )
        )
    finally:
        store.close()


def cmd_run(args: argparse.Namespace) -> None:
    session_dir = Path(args.sessions_dir) / args.session_id
    store = SessionStore(session_dir)
    max_depth = args.max_depth or store.get_meta("max_depth", 2)
    max_searches = args.max_searches or store.get_meta("max_searches", 25)
    executed = []

    try:
        with PoliteHTTPClient() as http:
            while store.search_count() < max_searches:
                leads = store.next_leads(max_depth=max_depth, limit=5)
                if not leads:
                    break
                for lead in leads:
                    if store.search_count() >= max_searches:
                        break
                    col_name = lead["collector"]
                    target = lead["target"]
                    if col_name not in COLLECTOR_REGISTRY:
                        store.mark_lead(lead["id"], "skipped")
                        continue
                    if store.has_searched(col_name, target):
                        store.mark_lead(lead["id"], "done")
                        continue
                    collector = COLLECTOR_REGISTRY[col_name]()
                    result = collector.run(target, http)
                    _ingest_collector_result(store, result, depth=lead["depth"])
                    store.mark_lead(lead["id"], "done")
                    executed.append(
                        {
                            "collector": col_name,
                            "target": target,
                            "status": result.status,
                            "sources": len(result.sources),
                            "findings": len(result.findings),
                            "error": result.error,
                        }
                    )
        store.export_snapshot()
        print(json.dumps({"session_id": args.session_id, "executed": executed}, indent=2))
    finally:
        store.close()


def cmd_add_finding(args: argparse.Namespace) -> None:
    session_dir = Path(args.sessions_dir) / args.session_id
    store = SessionStore(session_dir)
    try:
        for url in args.source_url:
            store.add_source(url, title=args.source_title or url, collector="agent_search")
        added = store.add_finding(
            category=args.category,
            claim=args.claim,
            confidence=normalize_confidence(args.confidence),
            source_urls=args.source_url,
            rationale=args.rationale,
            is_fact=not args.assumption,
            published_date=args.published_date or "",
            conflicts_with=args.conflicts_with or "",
        )
        store.export_snapshot()
        print(json.dumps({"added": added}))
    finally:
        store.close()


def cmd_report(args: argparse.Namespace) -> None:
    session_dir = Path(args.sessions_dir) / args.session_id
    store = SessionStore(session_dir)
    try:
        out = Path(args.output) if args.output else (session_dir / "intelligence_report.md")
        generate_report(store, out)
        print(json.dumps({"report_path": str(out.resolve())}))
    finally:
        store.close()


def cmd_list_collectors(_args: argparse.Namespace) -> None:
    items = [
        {"name": name, "description": cls.description, "requires_api_key": cls.requires_api_key}
        for name, cls in COLLECTOR_REGISTRY.items()
    ]
    print(json.dumps(items, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(prog="osint-engine", description="Autonomous OSINT Research Engine CLI")
    parser.add_argument("--sessions-dir", default=str(DEFAULT_SESSIONS_DIR), help="Directory for session data")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Classify input and initialize a persistent research session")
    p_init.add_argument("subject", help="Any research subject (name, domain, IP, handle, phrase, etc.)")
    p_init.add_argument("--session-id", default=None)
    p_init.add_argument("--max-depth", type=int, default=2)
    p_init.add_argument("--max-searches", type=int, default=25)
    p_init.set_defaults(func=cmd_init)

    p_run = sub.add_parser("run", help="Execute pending leads in a session within depth/budget limits")
    p_run.add_argument("session_id")
    p_run.add_argument("--max-depth", type=int, default=None)
    p_run.add_argument("--max-searches", type=int, default=None)
    p_run.set_defaults(func=cmd_run)

    p_find = sub.add_parser("add-finding", help="Record an agent-discovered finding with citations")
    p_find.add_argument("session_id")
    p_find.add_argument("--category", required=True)
    p_find.add_argument("--claim", required=True)
    p_find.add_argument("--confidence", default="MODERATE")
    p_find.add_argument("--source-url", action="append", required=True)
    p_find.add_argument("--source-title", default="")
    p_find.add_argument("--rationale", default="")
    p_find.add_argument("--published-date", default="")
    p_find.add_argument("--conflicts-with", default="")
    p_find.add_argument("--assumption", action="store_true")
    p_find.set_defaults(func=cmd_add_finding)

    p_rep = sub.add_parser("report", help="Generate the 15-section intelligence report")
    p_rep.add_argument("session_id")
    p_rep.add_argument("--output", default=None)
    p_rep.set_defaults(func=cmd_report)

    p_list = sub.add_parser("list-collectors", help="List registered OSINT collectors")
    p_list.set_defaults(func=cmd_list_collectors)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
