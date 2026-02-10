"""
============================================================
Agentic Bug Hunter — Coordinator (Main Entry Point)
============================================================
Orchestrates the full bug detection pipeline by invoking
each specialized agent in sequence.

Pipeline (Hybrid — Deterministic-First, LLM Fallback):
    IngestionAgent → ContextInferenceAgent → MCPRetrievalAgent
                                                    ↓
                                          CodeAnalysisAgent
                                                    ↓
                                          [BUG FOUND?]
                                          ├── YES → ExplanationAgent → CSV
                                          └── NO  → LLMCodeAnalysisAgent
                                                    ↓
                                              MCPValidatorAgent
                                                    ↓
                                              [VALIDATED?]
                                              ├── NO  → default
                                              └── YES → ExplanationAgent
                                                        + RuleLearningAgent → CSV

Usage:
    # Start MCP server first (separate terminal):
    python server/mcp_server.py

    # Run the pipeline:
    python code/main.py

    # Run without MCP server (rules-only mode):
    python code/main.py --no-mcp

    # Run without LLM fallback:
    python code/main.py --no-llm
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
from agents.llm_analysis_agent import LLMCodeAnalysisAgent
from agents.mcp_validator_agent import MCPValidatorAgent
from agents.rule_learning_agent import RuleLearningAgent
from models.data_models import RuleViolation
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
    print("   [*] Agentic Bug Hunter")
    print("   Hybrid C++ Bug Detection System")
    print("   Deterministic Rules + LLM Fallback + MCP")
    print('   "LLM proposes, MCP validates, rules enforce."')
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
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM fallback (deterministic rules only)"
    )
    return parser.parse_args()


def run_pipeline(input_path: str, output_path: str, use_mcp: bool = True, use_llm: bool = True):
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
    # PHASE 2.5: LLM Fallback (for unmatched samples)
    # ══════════════════════════════════════════════════════
    llm_upgraded = 0
    llm_rejected = 0
    rules_learned = 0

    if use_llm:
        logger.info("═" * 50)
        logger.info("PHASE 2.5: LLM Fallback Analysis")
        logger.info("═" * 50)

        # Count how many samples need LLM
        unmatched = [
            s for s in samples
            if violations[s.id].rule_name == "no_match"
        ]
        logger.info(f"  {len(unmatched)} sample(s) need LLM fallback.")

        if unmatched:
            llm_agent = LLMCodeAnalysisAgent()
            mcp_validator = MCPValidatorAgent()
            rule_learner = RuleLearningAgent()

            for sample in unmatched:
                # ── Stage 2A: LLM Analysis ─────────────────
                finding = llm_agent.analyze(
                    sample=sample,
                    context=contexts[sample.id],
                    mcp_results=mcp_results[sample.id],
                )

                if not finding or not finding.bug_detected:
                    logger.info(
                        f"  ID={sample.id}: LLM found no bug, keeping default."
                    )
                    continue

                # ── Stage 2B: MCP Validation ───────────────
                validation = mcp_validator.validate(
                    finding=finding,
                    mcp_results=mcp_results[sample.id],
                    sample=sample,
                )

                if not validation.validated:
                    logger.info(
                        f"  ID={sample.id}: MCP rejected LLM finding — "
                        f"{validation.validation_reason}"
                    )
                    llm_rejected += 1
                    continue

                # ── Stage 2C: Upgrade the violation ────────
                # Build MCP citation
                mcp_cite = ""
                if validation.supporting_docs:
                    mcp_cite = (
                        f" | According to documentation: "
                        f"{validation.supporting_docs[0][:100]}"
                    )

                explanation = (
                    f"Line {finding.bug_line}: {finding.bug_type} — "
                    f"{finding.reasoning[:350]}"
                    f"{mcp_cite}"
                )

                violations[sample.id] = RuleViolation(
                    rule_name=f"llm_{finding.bug_type}",
                    line_number=finding.bug_line,
                    line_content="",
                    explanation=explanation,
                    confidence=finding.confidence,
                    severity="warning",
                )
                llm_upgraded += 1

                # ── Stage 2D: Learn the rule ───────────────
                learned = rule_learner.learn(finding, validation)
                if learned:
                    rules_learned += 1

        logger.info(
            f"LLM fallback complete: {llm_upgraded} upgraded, "
            f"{llm_rejected} rejected, {rules_learned} rules learned.\n"
        )
    else:
        logger.info("LLM fallback disabled (--no-llm flag).\n")

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

    csv_validation = validate_output_csv(output_file)
    if csv_validation["valid"]:
        logger.info("✓ Output CSV validation PASSED")
    else:
        logger.warning("✗ Output CSV validation FAILED:")
        for error in csv_validation["errors"]:
            logger.warning(f"  - {error}")

    # ── Print summary ──────────────────────────────────────
    elapsed = time.time() - start_time
    print()
    print("=" * 60)
    print("   PIPELINE COMPLETE")
    print("=" * 60)
    print(f"   Samples processed:  {len(samples)}")
    print(f"   Reports generated:  {len(reports)}")
    print(f"   LLM upgrades:       {llm_upgraded}")
    print(f"   LLM rejected:       {llm_rejected}")
    print(f"   Rules learned:      {rules_learned}")
    print(f"   Output file:        {output_file}")
    print(f"   MCP integration:    {'active' if use_mcp else 'disabled'}")
    print(f"   LLM fallback:       {'active' if use_llm else 'disabled'}")
    print(f"   Validation:         {'PASSED' if csv_validation['valid'] else 'FAILED'}")
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
        if args.no_llm:
            config.LLM_FALLBACK_ENABLED = False
        run_pipeline(
            input_path=args.input,
            output_path=args.output,
            use_mcp=not args.no_mcp,
            use_llm=not args.no_llm and config.LLM_FALLBACK_ENABLED,
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
