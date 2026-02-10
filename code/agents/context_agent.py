"""
============================================================
PHASE 1: Context Inference Agent
============================================================
Responsibility:
    Analyze code structure and Context field to infer intent,
    extract RDI API references, and generate MCP search queries.

Input:  SampleRecord (id, code, context)
Output: InferredContext (api_calls, methods, queries, parsed lines)

Design Notes:
    - Parses code into numbered lines for analysis
    - Extracts all rdi.xxx() API chains from both code and context
    - Generates targeted MCP queries from context + API names
    - No bug detection at this stage — pure interpretation
============================================================
"""

import re
import logging
from typing import List

from models.data_models import SampleRecord, InferredContext, CodeLine

logger = logging.getLogger(__name__)

# ── Regex patterns for RDI API extraction ──────────────────
RDI_CHAIN_PATTERN = re.compile(
    r'rdi\.[\w()."\',:+\-*/\s]*(?:;|$)',
    re.MULTILINE
)
RDI_METHOD_PATTERN = re.compile(r'\.(\w+)\s*\(')
RDI_ROOT_PATTERN = re.compile(r'rdi\.(\w+)')


class ContextInferenceAgent:
    """
    Agent #2: Context Inference
    Infers the developer's intent from code structure and
    the Context field. Prepares data for downstream agents.
    """

    def __init__(self):
        logger.info("ContextInferenceAgent initialized.")

    def infer(self, sample: SampleRecord) -> InferredContext:
        """
        Analyze code and context to extract API usage and intent.

        Args:
            sample: SampleRecord with code and optional context

        Returns:
            InferredContext with parsed lines, APIs, and search queries
        """
        logger.debug(f"Inferring context for sample ID={sample.id}")

        # ── Step 1: Parse code into numbered lines ─────────
        code_lines = self._parse_code_lines(sample.code)

        # ── Step 2: Extract API calls and methods ──────────
        api_calls = self._extract_api_calls(sample.code)
        api_methods = self._extract_methods(sample.code, sample.context)

        # ── Step 3: Generate MCP search queries ────────────
        search_queries = self._generate_queries(
            sample.context, api_methods, api_calls
        )

        result = InferredContext(
            sample_id=sample.id,
            api_calls=api_calls,
            api_methods=api_methods,
            search_queries=search_queries,
            code_lines=code_lines,
        )

        logger.debug(f"  ID={sample.id}: {len(code_lines)} lines, "
                      f"{len(api_methods)} methods, {len(search_queries)} queries")
        return result

    def _parse_code_lines(self, code: str) -> List[CodeLine]:
        """Split code into numbered CodeLine objects."""
        raw_lines = code.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        return [
            CodeLine(
                line_number=i + 1,
                content=line,
                stripped=line.strip(),
            )
            for i, line in enumerate(raw_lines)
        ]

    def _extract_api_calls(self, code: str) -> List[str]:
        """Extract full rdi.xxx() call chains from code."""
        matches = RDI_CHAIN_PATTERN.findall(code)
        return [m.strip().rstrip(";").strip() for m in matches if m.strip()]

    def _extract_methods(self, code: str, context: str) -> List[str]:
        """Extract unique method names from code and context."""
        combined = f"{code}\n{context}"
        methods = []

        # Extract from .method() patterns
        for match in RDI_METHOD_PATTERN.findall(combined):
            if match not in methods:
                methods.append(match)

        # Extract rdi root methods
        for match in RDI_ROOT_PATTERN.findall(combined):
            if match not in methods:
                methods.append(match)

        return methods

    def _generate_queries(
        self, context: str, methods: List[str], api_calls: List[str]
    ) -> List[str]:
        """Generate search queries for MCP server."""
        queries = []

        # Query 1: Direct context query (most valuable)
        if context:
            # Use first meaningful line of context
            first_line = context.split("\n")[0].strip()
            if first_line:
                queries.append(first_line)

        # Query 2: Key API method query
        key_methods = [m for m in methods
                       if m not in ("pin", "execute", "begin", "end", "id")]
        if key_methods:
            query = f"rdi {' '.join(key_methods[:4])} parameters usage"
            queries.append(query)

        # Query 3: Specific API chain query (first chain in code)
        if api_calls:
            # Use the first substantial API call
            for call in api_calls:
                if len(call) > 20:
                    queries.append(call[:100])
                    break

        return queries[:3]
