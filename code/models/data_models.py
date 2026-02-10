"""
============================================================
Data Models — Evaluation Mode
============================================================
Type-safe data contracts between agents.
Designed for evaluation mode: only ID and Code are available.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SampleRecord:
    """
    Raw record from evaluation CSV.
    Produced by: IngestionAgent
    Consumed by: ContextInferenceAgent, CodeAnalysisAgent
    """
    id: int
    code: str                    # C++ code snippet (may be buggy)
    # Optional fields (available in training, not in evaluation)
    explanation: str = ""
    context: str = ""
    correct_code: str = ""


@dataclass
class CodeLine:
    """A single line of code with its line number."""
    line_number: int             # 1-indexed
    content: str                 # Raw content
    stripped: str                # Whitespace-stripped content


@dataclass
class InferredContext:
    """
    Inferred context from code structure.
    Produced by: ContextInferenceAgent
    Consumed by: MCPRetrievalAgent, ExplanationAgent
    """
    sample_id: int
    api_calls: List[str]         # Extracted rdi API chains
    api_methods: List[str]       # Individual method names
    search_queries: List[str]    # Queries for MCP server
    code_lines: List[CodeLine]   # Parsed code lines


@dataclass
class MCPResult:
    """
    Document retrieved from MCP server.
    Produced by: MCPRetrievalAgent
    Consumed by: ExplanationAgent
    """
    text: str
    score: float


@dataclass
class RuleViolation:
    """
    A single rule violation detected in the code.
    Produced by: CodeAnalysisAgent
    """
    rule_name: str               # e.g., "lifecycle_order"
    line_number: int             # 1-indexed line in code
    line_content: str            # Content of the buggy line
    explanation: str             # Human-readable explanation
    confidence: float            # 0.0 to 1.0
    severity: str = "error"      # "error", "warning"


@dataclass
class BugReport:
    """
    Final output record for output.csv.
    Produced by: ExplanationAgent
    Consumed by: CSV writer (main.py)
    """
    id: int
    bug_line: int
    explanation: str


@dataclass
class SuggestedRule:
    """
    A rule suggestion from the LLM for future deterministic detection.
    Produced by: LLMCodeAnalysisAgent
    Consumed by: RuleLearningAgent
    """
    rule_name: str              # snake_case identifier
    description: str            # What this rule enforces
    detection_pattern: str      # Regex or logic description
    severity: str = "HIGH"      # CRITICAL, HIGH, MEDIUM, LOW


@dataclass
class LLMFinding:
    """
    Structured output from LLM code analysis.
    Produced by: LLMCodeAnalysisAgent
    Consumed by: MCPValidatorAgent, ExplanationAgent
    """
    bug_detected: bool
    bug_line: int = 0
    bug_type: str = ""
    reasoning: str = ""
    confidence: float = 0.0
    suggested_rule: Optional[SuggestedRule] = None


@dataclass
class MCPValidation:
    """
    Validation result from MCP documentation check.
    Produced by: MCPValidatorAgent
    Consumed by: main.py pipeline, RuleLearningAgent
    """
    validated: bool
    supporting_docs: List[str] = field(default_factory=list)
    validation_reason: str = ""
