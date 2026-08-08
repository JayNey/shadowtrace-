#!/usr/bin/env python3
"""Classify pytest JUnit failures for CI summaries (ISSUE-267 / #863)."""

from __future__ import annotations

import argparse
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path


def _bucket(classname: str, message: str) -> str:
    text = f"{classname} {message}".lower()
    if any(
        token in text
        for token in (
            "postgres not reachable",
            "redis not reachable",
            "connection refused",
            "could not connect",
            "temporary failure in name resolution",
            "operationalerror",
            "docker",
        )
    ):
        return "infra"
    if "skip" in text or "skipped" in text:
        return "env_skip"
    if any(
        token in text
        for token in (
            "schema",
            "contract",
            "openapi",
            "model_json_schema",
            "committed schema",
            "serialization",
        )
    ):
        return "contract"
    return "product"


def classify_junit(paths: list[Path]) -> tuple[Counter[str], list[str]]:
    counts: Counter[str] = Counter()
    lines: list[str] = []
    for path in paths:
        if not path.is_file():
            continue
        root = ET.parse(path).getroot()
        suites = root.findall("testsuite")
        if root.tag == "testsuite":
            suites = [root]
        for suite in suites:
            for case in suite.findall("testcase"):
                classname = case.get("classname") or ""
                name = case.get("name") or ""
                failure = case.find("failure")
                error = case.find("error")
                skipped = case.find("skipped")
                if skipped is not None:
                    bucket = "env_skip"
                    detail = (skipped.get("message") or skipped.text or "").strip()
                    counts[bucket] += 1
                    lines.append(f"- [{bucket}] {classname}::{name}: {detail[:160]}")
                    continue
                node = failure if failure is not None else error
                if node is None:
                    continue
                detail = (node.get("message") or node.text or "").strip()
                bucket = _bucket(classname, detail)
                counts[bucket] += 1
                lines.append(f"- [{bucket}] {classname}::{name}: {detail[:160]}")
    return counts, lines


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("junit", nargs="+", type=Path)
    parser.add_argument("--github-summary", action="store_true")
    args = parser.parse_args()

    existing = [path for path in args.junit if path.is_file()]
    missing = [str(path) for path in args.junit if not path.is_file()]
    counts, lines = classify_junit(existing)

    summary = [
        "### ISSUE-267 pytest failure classification",
        "",
        f"- product: {counts.get('product', 0)}",
        f"- contract: {counts.get('contract', 0)}",
        f"- env_skip: {counts.get('env_skip', 0)}",
        f"- infra: {counts.get('infra', 0)}",
    ]
    if missing:
        summary.append(f"- missing_junit: {', '.join(missing)}")
    if lines:
        summary.extend(["", "#### Samples", *lines[:40]])
    else:
        summary.append("")
        summary.append("No failures/errors classified from available JUnit files.")

    text = "\n".join(summary) + "\n"
    print(text)
    if args.github_summary:
        summary_path = Path(os.environ.get("GITHUB_STEP_SUMMARY", ""))
        if str(summary_path):
            with summary_path.open("a", encoding="utf-8") as handle:
                handle.write(text)
    return 0


if __name__ == "__main__":
    import os

    raise SystemExit(main())
