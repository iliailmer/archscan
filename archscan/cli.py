import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from loguru import logger

from archscan.judge import TokenUsage, judge_project
from archscan.report import render, render_html
from archscan.scan import python as python_scan


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="archscan")
    parser.add_argument("path", type=Path)
    parser.add_argument("-o", "--output", type=Path, help="Write report to this file. Use .html for an HTML page.")
    args = parser.parse_args()

    logger.remove()
    logger.add(sys.stderr, level=os.getenv("ARCHSCAN_LOG", "INFO"), format="<level>{level: <7}</level> {message}")

    root = args.path.resolve()
    if not root.is_dir():
        sys.exit(f"Not a directory: {root}")

    project = python_scan.scan(root)
    logger.info("Scanned {} modules, {} dependencies", project.graph.number_of_nodes(), project.graph.number_of_edges())

    judgments = {}
    if os.getenv("TYPESAFE_API_KEY"):
        judgments, usage = judge_project(project)
        _log_usage(usage)
    else:
        logger.warning("TYPESAFE_API_KEY not set. Skipping classification.")

    render_fn = render_html if args.output and args.output.suffix == ".html" else render
    report = render_fn(project, judgments)
    if args.output:
        args.output.write_text(report)
        logger.info("Wrote {}", args.output)
    else:
        print(report)


def _log_usage(usage: TokenUsage) -> None:
    message = f"Tokens: {usage.input_tokens} in, {usage.output_tokens} out, {usage.calls} calls"
    price_in, price_out = os.getenv("ARCHSCAN_PRICE_IN"), os.getenv("ARCHSCAN_PRICE_OUT")
    if price_in and price_out:
        message += f". Estimated cost: ${usage.cost(float(price_in), float(price_out)):.4f}"
    logger.info(message)
