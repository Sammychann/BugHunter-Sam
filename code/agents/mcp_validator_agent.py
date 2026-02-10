"""
============================================================
PHASE 2.5: MCP Validator Agent
============================================================
Responsibility:
    Validate LLM-proposed bugs against MCP documentation.
    Prevents hallucinated bugs from reaching the output.

Input:  LLMFinding + List[MCPResult] + SampleRecord
Output: MCPValidation (validated / rejected with reason)

Design Notes:
    - Uses keyword and semantic overlap between LLM reasoning
      and MCP documentation to validate claims
    - Rejects findings with no documentation support
    - Acts as a hallucination firewall
============================================================
"""

import logging
import re
from typing import List

from models.data_models import (
    SampleRecord,
    MCPResult,
    LLMFinding,
    MCPValidation,
)
import config

logger = logging.getLogger(__name__)

# ── Minimum thresholds for validation ──────────────────────
MIN_KEYWORD_OVERLAP = 2    # Minimum shared keywords between LLM + MCP
MIN_DOC_SCORE = 0.2        # Minimum MCP doc score to consider


class MCPValidatorAgent:
    """
    Agent: MCP Documentation Validator
    Validates LLM-proposed bugs against MCP-retrieved
    documentation to prevent hallucinations.
    """

    def __init__(self):
        logger.info("MCPValidatorAgent initialized.")

    def validate(
        self,
        finding: LLMFinding,
        mcp_results: List[MCPResult],
        sample: SampleRecord,
    ) -> MCPValidation:
        """
        Validate an LLM finding against MCP documentation.

        Args:
            finding: LLM-proposed bug finding
            mcp_results: MCP documentation for this sample
            sample: Original sample record

        Returns:
            MCPValidation with validation result
        """
        logger.info(
            f"  ID={sample.id}: Validating LLM finding "
            f"(type={finding.bug_type}, line={finding.bug_line})"
        )

        # ── Quick reject: no bug detected ──────────────────
        if not finding.bug_detected:
            return MCPValidation(
                validated=False,
                validation_reason="LLM did not detect a bug.",
            )

        # ── Quick reject: low confidence ───────────────────
        if finding.confidence < config.LLM_CONFIDENCE_THRESHOLD:
            return MCPValidation(
                validated=False,
                validation_reason=(
                    f"LLM confidence {finding.confidence:.2f} is below "
                    f"threshold {config.LLM_CONFIDENCE_THRESHOLD}."
                ),
            )

        # ── Validate against MCP docs ──────────────────────
        if not mcp_results:
            # No MCP docs available — accept with warning if
            # confidence is very high
            if finding.confidence >= 0.85:
                logger.info(
                    f"  ID={sample.id}: No MCP docs, but LLM confidence "
                    f"{finding.confidence:.2f} >= 0.85 — accepting."
                )
                return MCPValidation(
                    validated=True,
                    supporting_docs=[],
                    validation_reason=(
                        "No MCP documentation available, but LLM confidence "
                        f"is very high ({finding.confidence:.2f})."
                    ),
                )
            return MCPValidation(
                validated=False,
                validation_reason="No MCP documentation available for validation.",
            )

        # ── Extract keywords from LLM reasoning ───────────
        llm_keywords = self._extract_keywords(
            f"{finding.reasoning} {finding.bug_type}"
        )

        # ── Check each MCP document for support ────────────
        supporting_docs = []
        total_overlap = 0

        for doc in mcp_results:
            if doc.score < MIN_DOC_SCORE:
                continue

            doc_keywords = self._extract_keywords(doc.text)
            overlap = llm_keywords & doc_keywords

            if len(overlap) >= MIN_KEYWORD_OVERLAP:
                snippet = doc.text[:200].strip()
                if len(doc.text) > 200:
                    snippet += "..."
                supporting_docs.append(snippet)
                total_overlap += len(overlap)

        # ── Decision ───────────────────────────────────────
        if supporting_docs:
            logger.info(
                f"  ID={sample.id}: MCP validation PASSED — "
                f"{len(supporting_docs)} supporting doc(s), "
                f"keyword overlap={total_overlap}"
            )
            return MCPValidation(
                validated=True,
                supporting_docs=supporting_docs,
                validation_reason=(
                    f"Found {len(supporting_docs)} supporting document(s) "
                    f"with {total_overlap} keyword overlaps."
                ),
            )

        # ── No documentation support found ─────────────────
        # Allow high-confidence findings even without docs
        if finding.confidence >= 0.9:
            logger.info(
                f"  ID={sample.id}: No direct MCP support, but "
                f"confidence {finding.confidence:.2f} >= 0.9 — accepting."
            )
            return MCPValidation(
                validated=True,
                supporting_docs=[],
                validation_reason=(
                    "No direct documentation support, but LLM confidence "
                    f"is very high ({finding.confidence:.2f})."
                ),
            )

        logger.info(
            f"  ID={sample.id}: MCP validation FAILED — "
            f"no supporting documentation found."
        )
        return MCPValidation(
            validated=False,
            supporting_docs=[],
            validation_reason=(
                "LLM finding could not be validated against MCP documentation. "
                "No supporting documents with sufficient keyword overlap found."
            ),
        )

    def _extract_keywords(self, text: str) -> set:
        """
        Extract meaningful keywords from text for overlap comparison.
        Filters out common stop words and short tokens.
        """
        # Tokenize on non-alphanumeric characters
        tokens = re.findall(r'[a-zA-Z_]\w{2,}', text)
        tokens = {t.lower() for t in tokens}

        # Remove very common stop words
        stop_words = {
            "the", "and", "for", "that", "this", "with", "from",
            "not", "are", "was", "but", "has", "had", "have",
            "been", "will", "can", "should", "would", "could",
            "may", "must", "shall", "used", "use", "using",
            "line", "code", "function", "method", "call",
            "value", "parameter", "argument", "type", "error",
            "bug", "issue", "incorrect", "wrong", "invalid",
        }
        return tokens - stop_words
