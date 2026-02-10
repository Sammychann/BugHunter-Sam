"""
============================================================
PHASE 3: Explanation Agent
============================================================
Responsibility:
    Generate concise, technically accurate explanations for
    detected bugs. Grounds explanations in MCP documentation.

Input:  RuleViolation + InferredContext + List[MCPResult]
Output: BugReport (final output record)

Design Notes:
    - Explanation comes from the rule violation description
    - Enriched with MCP documentation snippets when available
    - No hallucination — only reports what rules detected
    - Keeps explanations concise for judge readability
============================================================
"""

import logging
from typing import List

from models.data_models import (
    SampleRecord,
    InferredContext,
    MCPResult,
    RuleViolation,
    BugReport,
)
import config

logger = logging.getLogger(__name__)


class ExplanationAgent:
    """
    Agent #5: Explanation Generation
    Produces the final bug explanation by citing relevant RDI/SmartRDI documentation excerpts obtained from the MCP server, explaining how the detected code line violates a specific documented usage rule or lifecycle constraint.
    """

    def __init__(self):
        logger.info("ExplanationAgent initialized.")

    def explain(
        self,
        sample: SampleRecord,
        violation: RuleViolation,
        context: InferredContext,
        mcp_results: List[MCPResult],
    ) -> BugReport:
        """
        Generate a concise bug explanation from the rule violation.

        Args:
            sample: Original sample record
            violation: Rule violation from CodeAnalysisAgent
            context: Inferred context from ContextInferenceAgent
            mcp_results: Documentation from MCPRetrievalAgent

        Returns:
            BugReport ready for output.csv
        """
        logger.debug(f"Generating explanation for sample ID={sample.id}")

        # ── Start with rule-based explanation ──────────────
        explanation = violation.explanation

        # ── Enrich with MCP documentation if available ─────
        if mcp_results and violation.confidence < 0.95:
            mcp_context = self._extract_relevant_mcp(
                mcp_results, violation
            )
            if mcp_context:
                explanation = f"{explanation} {mcp_context}"

        # ── Clean and truncate ─────────────────────────────
        explanation = self._clean(explanation)

        if len(explanation) > config.MAX_EXPLANATION_LENGTH:
            explanation = explanation[:config.MAX_EXPLANATION_LENGTH - 3] + "..."

        report = BugReport(
            id=sample.id,
            bug_line=violation.line_number,
            explanation=explanation,
        )

        logger.info(f"  Report ID={sample.id}: line {report.bug_line}, "
                      f"rule={violation.rule_name}")
        return report

    def _extract_relevant_mcp(
        self, mcp_results: List[MCPResult], violation: RuleViolation
    ) -> str:
        """
        Extract relevant MCP documentation to support the explanation.
        Only includes documentation that relates to the detected bug.
        """
        if not mcp_results:
            return ""

        # Use highest-scoring result
        best = mcp_results[0]
        if best.score < 0.3:
            return ""

        # Take a brief snippet
        snippet = best.text[:150].strip()
        if len(best.text) > 150:
            snippet += "..."

        return f"(Documentation: {snippet})"

    def _clean(self, explanation: str) -> str:
        """Normalize whitespace and clean up the explanation."""
        return " ".join(explanation.split())
