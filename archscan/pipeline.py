import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from archscan.callgraph import build_call_graph
from archscan.catalog import Catalog, load_catalog
from archscan.coverage import Coverage, compute_coverage
from archscan.graph import ProjectGraph
from archscan.judge import Judgment, TokenUsage, judge_project
from archscan.scan import python as python_scan
from archscan.settings import LOG_HIDDEN, load_scan_settings
from archscan.trace import TraceResult, trace


@dataclass
class Analysis:
    root: Path
    full: ProjectGraph
    project: ProjectGraph
    catalog: Catalog
    result: TraceResult
    coverage: Coverage | None
    judgments: dict[str, Judgment]
    usage: TokenUsage | None


def analyze(root: Path, *, only: str | None = None, judge: bool | None = None) -> Analysis:
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    catalog = load_catalog(root)
    if only and only not in catalog.kinds():
        raise ValueError(f"Unknown trace kind: {only}. Valid kinds: {', '.join(catalog.kinds())}")

    try:
        skip = load_scan_settings(root)
    except (tomllib.TOMLDecodeError, ValueError) as error:
        raise ValueError(f"Invalid archscan.toml: {error}") from error

    full = python_scan.scan(root, skip=skip)
    shown = {d: n for d, n in full.skipped.items() if not d.startswith(".") and d not in LOG_HIDDEN}
    if shown:
        logger.info("Skipped {} files in: {}", sum(shown.values()), ", ".join(sorted(shown)))
    build_call_graph(full)
    coverage = compute_coverage(full)
    project = full.without_tests()
    build_call_graph(project)
    skipped = full.graph.number_of_nodes() - project.graph.number_of_nodes()
    logger.info("Found {} test modules, skipped in the report", skipped)
    logger.info("Scanned {} modules, {} dependencies", project.graph.number_of_nodes(), project.graph.number_of_edges())
    result = trace(project, catalog, only=only)
    findings = sum(len(t.findings) for t in result.traces.values())
    logger.info("Traced {} functions: {} findings", len(project.functions()), findings)
    if not result.converged:
        logger.warning("Trace did not converge; results may be incomplete.")

    judgments: dict[str, Judgment] = {}
    usage: TokenUsage | None = None
    do_judge = bool(os.getenv("TYPESAFE_API_KEY")) if judge is None else judge
    if do_judge:
        judgments, usage = judge_project(project, catalog)
        _log_usage(usage)
    elif judge is None:
        logger.warning("TYPESAFE_API_KEY not set. Skipping classification.")

    return Analysis(root, full, project, catalog, result, coverage, judgments, usage)


def _log_usage(usage: TokenUsage) -> None:
    message = f"Tokens: {usage.input_tokens} in, {usage.output_tokens} out, {usage.calls} calls"
    price_in, price_out = os.getenv("ARCHSCAN_PRICE_IN"), os.getenv("ARCHSCAN_PRICE_OUT")
    if price_in and price_out:
        message += f". Estimated cost: ${usage.cost(float(price_in), float(price_out)):.4f}"
    logger.info(message)
