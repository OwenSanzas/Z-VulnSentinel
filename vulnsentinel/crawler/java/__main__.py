"""CLI entry point: python -m vulnsentinel.crawler.java"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from vulnsentinel.crawler.health import run_health_check


def main() -> None:
    parser = argparse.ArgumentParser(description="Java artifact crawler")
    parser.add_argument("--top", type=int, default=100, help="Number of top artifacts to crawl")
    parser.add_argument("--check", action="store_true", help="Run health check on repos.json")
    parser.add_argument("--fix", action="store_true", help="Auto-fix branch mismatches")
    args, remaining = parser.parse_known_args()

    if args.check or args.fix:
        repos_json = Path(__file__).parent / "repos.json"
        report_md = Path(__file__).parent / "health_report.md"
        fix_args = ["--fix"] if args.fix else []
        sys.argv = [sys.argv[0]] + fix_args
        run_health_check("Java", repos_json, report_md)
        return

    from vulnsentinel.crawler.java import crawl_top, save

    print(f"Crawling top {args.top} Java artifacts from Maven Central...")
    entries = asyncio.run(crawl_top(args.top))
    save(entries)


main()
