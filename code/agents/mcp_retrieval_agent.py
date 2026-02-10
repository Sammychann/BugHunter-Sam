"""
============================================================
PHASE 2: MCP Bug Retrieval Agent
============================================================
Responsibility:
    Query the MCP server for relevant RDI/SmartRDI documentation
    to support bug detection and explanation enrichment.

Input:  InferredContext (search_queries)
Output: List[MCPResult] per sample

Design Notes:
    - Connects via FastMCP Client (SSE transport)
    - Calls search_documents tool for vector similarity retrieval
    - Gracefully falls back if MCP is unavailable
    - Results enrich explanations with documentation context
============================================================
"""

import asyncio
import logging
import json
from typing import List

from models.data_models import InferredContext, MCPResult
import config

logger = logging.getLogger(__name__)


class MCPRetrievalAgent:
    """
    Agent #3: MCP Document Retrieval
    Queries the MCP server's vector store for RDI documentation
    relevant to each code sample.
    """

    def __init__(self, server_url: str = None):
        self.server_url = server_url or config.MCP_SERVER_URL
        self._connected = None  # Will be set on first attempt
        logger.info(f"MCPRetrievalAgent initialized with server: {self.server_url}")

    def retrieve(self, context: InferredContext) -> List[MCPResult]:
        """
        Query MCP server with context-derived search queries.
        Synchronous wrapper around the async implementation.

        Args:
            context: InferredContext from ContextInferenceAgent

        Returns:
            List[MCPResult]: Ranked documentation snippets
        """
        if not config.MCP_ENABLED:
            return []

        # Skip if we already know the server is unavailable
        if self._connected is False:
            return []

        try:
            return asyncio.run(self._retrieve_async(context))
        except Exception as e:
            logger.warning(f"MCP retrieval failed for ID={context.sample_id}: {e}")
            self._connected = False
            return []

    async def _retrieve_async(self, context: InferredContext) -> List[MCPResult]:
        """Async implementation of MCP document retrieval."""
        all_results: List[MCPResult] = []

        try:
            from fastmcp import Client

            async with Client(self.server_url) as client:
                self._connected = True
                logger.debug(f"  MCP connected for sample ID={context.sample_id}")

                for query in context.search_queries:
                    try:
                        result = await client.call_tool(
                            "search_documents",
                            {"query": query}
                        )
                        parsed = self._parse_response(result)
                        all_results.extend(parsed)
                    except Exception as e:
                        logger.debug(f"  MCP query failed: {e}")
                        continue

        except Exception as e:
            logger.warning(f"MCP connection failed: {e}")
            self._connected = False

        # Deduplicate and sort by score
        unique = self._deduplicate(all_results)
        unique.sort(key=lambda r: r.score, reverse=True)
        return unique[:config.MCP_QUERY_TOP_K]

    def _parse_response(self, response) -> List[MCPResult]:
        """Parse FastMCP tool response into MCPResult objects."""
        results = []
        try:
            if isinstance(response, list):
                for item in response:
                    text = item.text if hasattr(item, 'text') else str(item)
                    try:
                        parsed = json.loads(text)
                        if isinstance(parsed, list):
                            for doc in parsed:
                                if isinstance(doc, dict):
                                    results.append(MCPResult(
                                        text=doc.get("text", ""),
                                        score=float(doc.get("score", 0.0))
                                    ))
                        elif isinstance(parsed, dict):
                            results.append(MCPResult(
                                text=parsed.get("text", ""),
                                score=float(parsed.get("score", 0.0))
                            ))
                    except (json.JSONDecodeError, TypeError):
                        results.append(MCPResult(text=text, score=0.5))
        except Exception as e:
            logger.debug(f"Parse error: {e}")
        return results

    def _deduplicate(self, results: List[MCPResult]) -> List[MCPResult]:
        """Remove duplicate results by text prefix."""
        seen = set()
        unique = []
        for r in results:
            key = r.text[:100].strip()
            if key and key not in seen:
                seen.add(key)
                unique.append(r)
        return unique
