"""
============================================================
PHASE 2.5: LLM Code Analysis Agent (Fallback)
============================================================
Responsibility:
    Analyze C++ code using Groq OSS-120B when deterministic
    rules detect no bug. Produces structured JSON findings.

Input:  SampleRecord + InferredContext + List[MCPResult]
Output: LLMFinding (structured bug analysis)

Design Notes:
    - ONLY invoked when deterministic engine returns "no_match"
    - Uses low temperature (0.15) for near-deterministic output
    - Demands structured JSON — no free-form text
    - Does NOT access MCP directly
    - Does NOT generate final explanations
============================================================
"""

import json
import logging
from typing import List, Optional

from groq import Groq

from models.data_models import (
    SampleRecord,
    InferredContext,
    MCPResult,
    LLMFinding,
    SuggestedRule,
)
import config

logger = logging.getLogger(__name__)

# ── System prompt for structured bug analysis ──────────────
SYSTEM_PROMPT = """You are an expert C++ static analysis engine specializing in RDI and SmartRDI APIs for semiconductor test systems.

You will be given a C++ code snippet that may contain a bug related to RDI/SmartRDI API usage. Analyze the code carefully.

You MUST respond with ONLY a valid JSON object (no markdown, no explanation outside JSON). The JSON must follow this exact schema:

{
  "bug_detected": true or false,
  "bug_line": <1-indexed line number where the bug manifests>,
  "bug_type": "<short snake_case label, e.g., 'missing_lifecycle_call', 'variable_mismatch'>",
  "reasoning": "<concise but precise explanation of the error>",
  "confidence": <float between 0.0 and 1.0>,
  "suggested_rule": {
    "rule_name": "<snake_case_name>",
    "description": "<what this rule enforces>",
    "detection_pattern": "<regex or logic description for detecting this bug>",
    "severity": "<CRITICAL|HIGH|MEDIUM|LOW>"
  }
}

== COMMON BUG CATEGORIES TO CHECK ==
1. **Lifecycle**: Missing `RDI_BEGIN()` or `RDI_END()`.
2. **Variable Consistency**: Pin names/Port names must match string literals (e.g. `rdi.digCap("cap")` vs `rdi.id("cap")`).
3. **Argument Validity**: Check for valid enums (`TA::VTT` vs `TA::VECD`), valid units (mA, V), and correct types.
4. **Ordering**: `iClamp(low, high)`, `RDI_BEGIN` comes first, `execute()` must be called on chains.
5. **Typos**: `iMeans` -> `iMeas`, `readHumanSeniority` -> `readHumSensor`.
6. **Bad Values**: `vForce` > `vForceRange`, `samples` > 8192.

== EXAMPLES ==
Code:
  rdi.dc().pin("d1").vForce(1 V);
Bug:
  {"bug_detected": true, "bug_line": 1, "bug_type": "missing_execute", "reasoning": "DC force configuration chain must end with .execute().", "confidence": 0.95, ...}

Code:
  rdi.smartVec().vecEditMode(TA::VECD);
Bug:
  {"bug_detected": true, "bug_line": 1, "bug_type": "invalid_enum", "reasoning": "vecEditMode requires TA::VTT for vector editing context, not TA::VECD.", "confidence": 0.9, ...}

Code:
  RDI_BEGIN();
  rdi.port("A").func("idd").burstRunTime("rt", 100).execute();
  auto x = rdi.id("id").getMultiPassFail();
Bug:
  {"bug_detected": true, "bug_line": 2, "bug_type": "variable_mismatch", "reasoning": "Retrieval uses rdi.id(\"id\") but setup used func(\"idd\"). Identifiers must match.", "confidence": 0.9, ...}

Rules:
- Identify the FIRST line where the bug manifests
- If you find no bug, set bug_detected to false
- Rate confidence HIGH (0.9+) for syntax/API misuse, MEDIUM (0.7+) for logic/context errors"""


class LLMCodeAnalysisAgent:
    """
    Agent: LLM-Based Code Analysis (Fallback)
    Uses Groq OSS-120B to analyze code that the deterministic
    engine could not classify.
    """

    def __init__(self):
        self.client = None
        self._initialized = False
        logger.info("LLMCodeAnalysisAgent initialized.")

    def _ensure_client(self):
        """Lazily initialize the Groq client."""
        if not self._initialized:
            try:
                self.client = Groq(api_key=config.GROQ_API_KEY)
                self._initialized = True
                logger.info("  Groq client connected.")
            except Exception as e:
                logger.error(f"  Failed to initialize Groq client: {e}")
                self._initialized = False

    def analyze(
        self,
        sample: SampleRecord,
        context: InferredContext,
        mcp_results: List[MCPResult],
    ) -> Optional[LLMFinding]:
        """
        Analyze code using Groq OSS-120B.

        Args:
            sample: Raw sample record with code
            context: Inferred context (API calls, methods)
            mcp_results: MCP documentation (for context only)

        Returns:
            LLMFinding if analysis succeeded, None on error
        """
        self._ensure_client()
        if not self.client:
            logger.warning(f"  ID={sample.id}: Groq client unavailable, skipping LLM.")
            return None

        logger.info(f"  ID={sample.id}: LLM fallback invoked (Groq OSS-120B)")

        # ── Build the user prompt ──────────────────────────
        user_prompt = self._build_prompt(sample, context)

        try:
            # ── Call Groq API ──────────────────────────────
            completion = self.client.chat.completions.create(
                model=config.GROQ_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=config.LLM_TEMPERATURE,
                max_completion_tokens=config.LLM_MAX_TOKENS,
                top_p=1,
                stream=False,
                stop=None,
            )

            # ── Parse response ─────────────────────────────
            response_text = completion.choices[0].message.content
            logger.debug(f"  ID={sample.id}: LLM raw response: {response_text[:200]}")

            finding = self._parse_response(response_text, sample.id)
            if finding:
                logger.info(
                    f"  ID={sample.id}: LLM finding — "
                    f"bug={finding.bug_detected}, line={finding.bug_line}, "
                    f"type={finding.bug_type}, conf={finding.confidence:.2f}"
                )
            return finding

        except Exception as e:
            logger.error(f"  ID={sample.id}: LLM analysis failed: {e}")
            return None

    def _build_prompt(
        self, sample: SampleRecord, context: InferredContext
    ) -> str:
        """Build the user prompt with code and context."""
        lines_numbered = "\n".join(
            f"{cl.line_number}: {cl.content}" for cl in context.code_lines
        )

        prompt_parts = [
            "Analyze the following C++ code for RDI/SmartRDI API bugs.",
            "",
            "== CODE (line-numbered) ==",
            lines_numbered,
        ]

        if context.api_methods:
            prompt_parts.extend([
                "",
                "== DETECTED API METHODS ==",
                ", ".join(context.api_methods),
            ])

        if sample.context:
            prompt_parts.extend([
                "",
                "== DEVELOPER CONTEXT ==",
                sample.context,
            ])

        prompt_parts.extend([
            "",
            "Respond with ONLY a JSON object. No markdown fences.",
        ])

        return "\n".join(prompt_parts)

    def _parse_response(
        self, response_text: str, sample_id: int
    ) -> Optional[LLMFinding]:
        """Parse LLM JSON response into LLMFinding."""
        if not response_text:
            return None

        # ── Strip markdown fences if present ───────────────
        text = response_text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            # Remove first and last lines (fences)
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON within the text
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    data = json.loads(text[start:end])
                except json.JSONDecodeError:
                    logger.warning(f"  ID={sample_id}: Could not parse LLM JSON")
                    return None
            else:
                logger.warning(f"  ID={sample_id}: No JSON found in LLM response")
                return None

        # ── Build LLMFinding ───────────────────────────────
        suggested_rule = None
        if "suggested_rule" in data and isinstance(data["suggested_rule"], dict):
            sr = data["suggested_rule"]
            suggested_rule = SuggestedRule(
                rule_name=sr.get("rule_name", "unknown_rule"),
                description=sr.get("description", ""),
                detection_pattern=sr.get("detection_pattern", ""),
                severity=sr.get("severity", "MEDIUM"),
            )

        return LLMFinding(
            bug_detected=bool(data.get("bug_detected", False)),
            bug_line=int(data.get("bug_line", 0)),
            bug_type=str(data.get("bug_type", "")),
            reasoning=str(data.get("reasoning", "")),
            confidence=float(data.get("confidence", 0.0)),
            suggested_rule=suggested_rule,
        )
