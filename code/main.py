"""
============================================================
Agentic Bug Hunter — Coordinator (Main Entry Point)
============================================================
Orchestrates the full bug detection pipeline by invoking
each specialized agent in sequence.

Pipeline:
    IngestionAgent → ContextInferenceAgent → MCPRetrievalAgent
                                                    ↓
    CSV Writer ← ExplanationAgent ← CodeAnalysisAgent

Usage:
    # Start MCP server first (separate terminal):
    python server/mcp_server.py

    # Run the pipeline:
    python code/main.py

    # Run without MCP server (rules-only mode):
    python code/main.py --no-mcp
============================================================
"""

import sys
import os
import logging
import time
import argparse

# ── Ensure code/ is on the Python path ─────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from agents.ingestion_agent import IngestionAgent
from agents.context_agent import ContextInferenceAgent
from agents.mcp_retrieval_agent import MCPRetrievalAgent
from agents.code_analysis_agent import CodeAnalysisAgent
from agents.explanation_agent import ExplanationAgent
from utils.csv_utils import write_output_csv, validate_output_csv

# ── Logging Setup ──────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("Coordinator")


def banner():
    """Print startup banner."""
    print()
    print("=" * 60)
    print("   🔍 Agentic Bug Hunter")
    print("   Rule-Based C++ Bug Detection System")
    print("   Infineon Challenge — Static Analysis + MCP")
    print("=" * 60)
    print()


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Agentic Bug Hunter — Detect bugs in C++ RDI code"
    )
    parser.add_argument(
        "--input", "-i",
        default=config.SAMPLES_CSV_PATH,
        help="Path to input CSV file (default: samples.csv)"
    )
    parser.add_argument(
        "--output", "-o",
        default=config.OUTPUT_CSV_PATH,
        help="Path to output CSV file (default: output.csv)"
    )
    parser.add_argument(
        "--no-mcp",
        action="store_true",
        help="Skip MCP server queries (rules-only mode)"
    )
    return parser.parse_args()


def run_pipeline(input_path: str, output_path: str, use_mcp: bool = True):
    """
    Execute the full bug detection pipeline.

    Phase 1: Data Ingestion & Context Inference
    Phase 2: MCP Retrieval & Code Analysis
    Phase 3: Explanation Generation & CSV Output
    Phase 4: Validation
    """
    banner()
    start_time = time.time()

    # ══════════════════════════════════════════════════════
    # PHASE 1: Data Ingestion & Context Inference
    # ══════════════════════════════════════════════════════
    logger.info("═" * 50)
    logger.info("PHASE 1: Data Ingestion & Context Inference")
    logger.info("═" * 50)

    ingestion_agent = IngestionAgent(input_path)
    samples = ingestion_agent.load()
    logger.info(f"Loaded {len(samples)} samples.\n")

    context_agent = ContextInferenceAgent()
    contexts = {}
    for sample in samples:
        ctx = context_agent.infer(sample)
        contexts[sample.id] = ctx
    logger.info(f"Inferred context for {len(contexts)} samples.\n")

    # ══════════════════════════════════════════════════════
    # PHASE 2: MCP Retrieval & Code Analysis
    # ══════════════════════════════════════════════════════
    logger.info("═" * 50)
    logger.info("PHASE 2: MCP Retrieval & Rule-Based Analysis")
    logger.info("═" * 50)

    mcp_agent = MCPRetrievalAgent()
    mcp_results = {}

    if use_mcp:
        for sample in samples:
            results = mcp_agent.retrieve(contexts[sample.id])
            mcp_results[sample.id] = results
            if results:
                logger.info(f"  MCP: {len(results)} docs for ID={sample.id}")
        logger.info(f"MCP retrieval complete.\n")
    else:
        logger.info("MCP disabled (--no-mcp flag). Using rules-only mode.\n")
        for sample in samples:
            mcp_results[sample.id] = []

    analysis_agent = CodeAnalysisAgent()
    violations = {}
    for sample in samples:
        violation = analysis_agent.analyze(
            sample=sample,
            context=contexts[sample.id],
            mcp_results=mcp_results[sample.id],
        )
        violations[sample.id] = violation
    logger.info(f"Code analysis complete for {len(violations)} samples.\n")

    # ══════════════════════════════════════════════════════
    # PHASE 3: Explanation & Output Generation
    # ══════════════════════════════════════════════════════
    logger.info("═" * 50)
    logger.info("PHASE 3: Explanation & Output Generation")
    logger.info("═" * 50)

    explanation_agent = ExplanationAgent()
    reports = []
    for sample in samples:
        report = explanation_agent.explain(
            sample=sample,
            violation=violations[sample.id],
            context=contexts[sample.id],
            mcp_results=mcp_results[sample.id],
        )
        reports.append(report)
    logger.info(f"Generated {len(reports)} bug reports.\n")

    output_file = write_output_csv(reports, output_path)

    # ══════════════════════════════════════════════════════
    # PHASE 4: Validation & Summary
    # ══════════════════════════════════════════════════════
    logger.info("═" * 50)
    logger.info("PHASE 4: Validation & Summary")
    logger.info("═" * 50)

    validation = validate_output_csv(output_file)
    if validation["valid"]:
        logger.info("✓ Output CSV validation PASSED")
    else:
        logger.warning("✗ Output CSV validation FAILED:")
        for error in validation["errors"]:
            logger.warning(f"  - {error}")

    # ── Print summary ──────────────────────────────────────
    elapsed = time.time() - start_time
    print()
    print("=" * 60)
    print("   PIPELINE COMPLETE")
    print("=" * 60)
    print(f"   Samples processed:  {len(samples)}")
    print(f"   Reports generated:  {len(reports)}")
    print(f"   Output file:        {output_file}")
    print(f"   MCP integration:    {'active' if use_mcp else 'disabled'}")
    print(f"   Validation:         {'PASSED' if validation['valid'] else 'FAILED'}")
    print(f"   Total time:         {elapsed:.2f}s")
    print("=" * 60)
    print()

    # ── Results table ──────────────────────────────────────
    print("+" + "-"*4 + "+" + "-"*10 + "+" + "-"*20 + "+" + "-"*44 + "+")
    print(f"| {'ID':>2} | {'Bug Line':>8} | {'Rule':<18} | {'Explanation (preview)':<42} |")
    print("+" + "-"*4 + "+" + "-"*10 + "+" + "-"*20 + "+" + "-"*44 + "+")
    for r in sorted(reports, key=lambda x: x.id):
        rule = violations[r.id].rule_name[:18]
        exp = r.explanation[:42] + "..." if len(r.explanation) > 42 else r.explanation
        print(f"| {r.id:>2} | {r.bug_line:>8} | {rule:<18} | {exp:<42} |")
    print("+" + "-"*4 + "+" + "-"*10 + "+" + "-"*20 + "+" + "-"*44 + "+")

    return reports


if __name__ == "__main__":
    args = parse_args()

    try:
        config.MCP_ENABLED = not args.no_mcp
        run_pipeline(
            input_path=args.input,
            output_path=args.output,
            use_mcp=not args.no_mcp,
        )
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Pipeline interrupted.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Pipeline failed: {e}", exc_info=True)
        sys.exit(1)
