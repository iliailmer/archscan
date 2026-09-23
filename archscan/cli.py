import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from loguru import logger

from archscan.export import to_json
from archscan.pipeline import analyze
from archscan.report import render, render_html


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="archscan")
    parser.add_argument("path", type=Path)
    parser.add_argument("-o", "--output", type=Path, help="Write report to this file. Use .html for an HTML page.")
    parser.add_argument("--trace", metavar="KIND", help="Trace only this source kind, for example env.")
    args = parser.parse_args()

    logger.remove()
    logger.add(sys.stderr, level=os.getenv("ARCHSCAN_LOG", "INFO"), format="<level>{level: <7}</level> {message}")

    try:
        analysis = analyze(args.path, only=args.trace)
    except (ValueError, NotADirectoryError) as error:
        sys.exit(str(error))

    if args.output and args.output.suffix == ".json":
        report = json.dumps(to_json(analysis), indent=1)
    else:
        render_fn = render_html if args.output and args.output.suffix == ".html" else render
        report = render_fn(analysis.project, analysis.judgments, analysis.result, coverage=analysis.coverage)
    if args.output:
        args.output.write_text(report)
        logger.info("Wrote {}", args.output)
    else:
        print(report)
