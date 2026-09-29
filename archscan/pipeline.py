import tomllib
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from archscan.callgraph import build_call_graph
from archscan.capabilities import derive_capabilities
from archscan.catalog import load_catalog
from archscan.coverage import Coverage, compute_coverage
from archscan.graph import ProjectGraph
from archscan.judge import NOUL_THRESHOLD, Judgment, TokenUsage, judge_project
from archscan.scan import python as python_scan
from archscan.settings import load_scan_settings
from archscan.trace import TraceResult, trace


@dataclass
class Analysis:
    root: Path
    full: ProjectGraph
    project: ProjectGraph
    result: TraceResult
    coverage: Coverage | None
    judgments: dict[str, Judgment]
    capabilities: dict[str, list[str]]


def analyze(root: Path, *, only: str | None = None, judge: bool = False) -> Analysis:
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
    shown = {d: n for d, n in full.skipped.items() if not d.startswith(".")}
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

    capabilities = {m.name: derive_capabilities(project, catalog, m.name) for m in project.modules()}

    judgments: dict[str, Judgment] = {}
    if judge:
        judgments, usage = judge_project(project)
        _log_usage(usage)
        for name, judgment in judgments.items():
            if judgment.handles_auth >= NOUL_THRESHOLD:
                capabilities[name] = sorted({*capabilities[name], "handles_auth"})

    return Analysis(root, full, project, result, coverage, judgments, capabilities)


def _log_usage(usage: TokenUsage) -> None:
    logger.info("Tokens: {} in, {} out, {} calls", usage.input_tokens, usage.output_tokens, usage.calls)
