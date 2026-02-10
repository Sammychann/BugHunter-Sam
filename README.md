# 🔍 Agentic Bug Hunter

> **Deterministic, rule-based bug detection for C++ RDI/SmartRDI code.**  
> Built for the Infineon "Agentic Bug Hunter" Challenge.

---

## Why No LLM?

This system **intentionally avoids Large Language Models (LLMs)** for bug detection:

| Concern | LLM Approach | Our Approach |
|---|---|---|
| **Determinism** | Same input → different output | Same input → same output, always |
| **Explainability** | "The model thinks…" | "Rule X fired because condition Y was met on line Z" |
| **Reliability** | Hallucinations possible | Only reports what rules explicitly detect |
| **Speed** | API latency, token costs | Sub-second per sample |
| **Auditability** | Black box | Every detection traceable to a named rule |

**Every bug report links directly to a specific, named rule** — no probabilistic reasoning, no API keys, no external dependencies beyond the MCP document server.

---

## Architecture

```
┌──────────────┐     ┌────────────────────┐     ┌──────────────────┐
│  Ingestion   │────▶│ Context Inference  │────▶│  MCP Retrieval   │
│    Agent     │     │      Agent         │     │     Agent        │
│              │     │                    │     │                  │
│ Reads CSV:   │     │ • Parse code lines │     │ • Query MCP      │
│ ID, Context, │     │ • Extract APIs     │     │   server         │
│ Code         │     │ • Build queries    │     │ • Retrieve docs  │
└──────────────┘     └────────────────────┘     └────────┬─────────┘
                                                          │
┌──────────────┐     ┌────────────────────┐              │
│  Output CSV  │◀────│   Explanation      │◀─────────────┤
│  Writer      │     │     Agent          │     ┌────────┴─────────┐
│              │     │                    │     │  Code Analysis   │
│ ID, Bug Line,│     │ • Format output    │◀────│     Agent        │
│ Explanation  │     │ • Enrich with MCP  │     │                  │
└──────────────┘     └────────────────────┘     │ 21 static rules  │
                                                 │ Deterministic    │
                                                 └──────────────────┘
```

### Agent Responsibilities

| Agent | Input | Output | Role |
|---|---|---|---|
| **IngestionAgent** | CSV file | `List[SampleRecord]` | Parse evaluation CSV (ID, Context, Code) |
| **ContextInferenceAgent** | SampleRecord | `InferredContext` | Extract RDI API calls, parse lines, generate MCP queries |
| **MCPRetrievalAgent** | InferredContext | `List[MCPResult]` | Query MCP vector store for relevant documentation |
| **CodeAnalysisAgent** | Sample + Context + MCP | `RuleViolation` | Apply 21 static analysis rules to find the bug |
| **ExplanationAgent** | Violation + MCP | `BugReport` | Generate concise, grounded explanation |
| **Coordinator** (main.py) | — | output.csv | Orchestrate pipeline, validate output |

---

## How MCP Provides Semantic Understanding

The MCP (Model Context Protocol) server provides **domain knowledge retrieval** without requiring an LLM:

1. **Vector Store**: Pre-indexed RDI/SmartRDI documentation using BAAI/bge-base-en-v1.5 embeddings
2. **Semantic Search**: `search_documents(query)` returns documentation snippets ranked by relevance
3. **Context Enrichment**: Retrieved docs enrich bug explanations with official API documentation

```
Code Analysis Agent detects: "iClamp arguments swapped"
         ↓
MCP query: "rdi iClamp parameter order usage"
         ↓
MCP returns: "iClamp(low, high) sets current clamp limits..."
         ↓
Final explanation includes documentation reference
```

The MCP server is **optional** — the system works fully without it (`--no-mcp` flag). When available, it adds documentation context to explanations.

---

## Bug Detection Rules

The CodeAnalysisAgent implements **21 deterministic rules** organized into 6 categories:

### Category 1: Lifecycle Rules
| Rule | Description | Example |
|---|---|---|
| `lifecycle_order` | RDI_BEGIN() must precede RDI_END() | `RDI_END(); ... RDI_BEGIN();` → error |

### Category 2: API Name Validation  
| Rule | Description | Example |
|---|---|---|
| `gibberish_names` | Detect corrupted function names via consonant clusters | `getVesjkctor()` → `getVector()` |
| `known_typos` | Map known wrong names to correct ones | `iMeans()` → `iMeas()` |
| `case_sensitivity` | RDI APIs use camelCase | `imeasRange()` → `iMeasRange()` |

### Category 3: Argument Validation
| Rule | Description | Example |
|---|---|---|
| `iclamp_arg_order` | iClamp(low, high) — first ≤ second | `iClamp(50, -50)` → swap |
| `vforce_range` | vForce must not exceed vForceRange | `vForce(31).vForceRange(30)` → overflow |
| `invalid_vforce_range_val` | vForceRange must be a valid AVI64 range | `vForceRange(35 V)` → invalid |
| `samples_max` | samples() ≤ 8192 | `samples(9216)` → exceeds max |
| `extra_parameters` | Functions with no params called with args | `readTempThresh(70)` → no args |
| `missing_parameters` | Required params missing | `getAlarmValue()` → needs pin |
| `bool_args` | Boolean argument correctness | `digCapBurstSiteUpload(false)` → true |
| `unit_validation` | Valid RDI units only | `mAh` → `mA` |

### Category 4: Method Chain Validation
| Rule | Description | Example |
|---|---|---|
| `duplicate_calls` | Consecutive same method calls | `.end().end()` → remove duplicate |
| `terminal_method` | DC chains end with `.execute()` | `.read()` → `.execute()` |
| `chain_order` | Correct method chain ordering | `rdi.burstUpload.smartVec()` → swap |

### Category 5: Consistency Checks
| Rule | Description | Example |
|---|---|---|
| `pin_consistency` | Setup pins must match retrieval pins | pin `D0` vs `DO` mismatch |
| `pin_mismatch_in_chain` | Related operations use same pins | `DPS_1,DPS_2` vs `DPS_0,DPS_1` |
| `invalid_vector_method` | Valid C++ vector methods only | `.push_forward()` → `.push_back()` |
| `variable_consistency` | Variables must be declared | `vec_port2` used but `vec_port1` declared |

### Category 6: Scope Rules
| Rule | Description | Example |
|---|---|---|
| `enum_validation` | Correct enum for context | `TA::VECD` with `copyLabel` → `TA::VTT` |
| `scope_violation` | Operations in correct block | `retrievePmuxPinStatus` inside RDI → after |

---

## Execution Flow

```bash
# 1. Start MCP server (optional, in separate terminal)
python server/mcp_server.py

# 2. Run pipeline
python code/main.py

# 3. Or run without MCP (rules-only)
python code/main.py --no-mcp

# 4. Custom input/output paths
python code/main.py --input path/to/input.csv --output path/to/output.csv
```

### Pipeline Phases

```
Phase 1: Data Ingestion & Context Inference
  ├── Load CSV (ID, Context, Code)
  ├── Parse code into numbered lines
  └── Extract RDI API chains and methods

Phase 2: MCP Retrieval & Rule-Based Analysis
  ├── Query MCP server with inferred API names
  ├── Apply 21 static analysis rules
  └── Select highest-confidence violation

Phase 3: Explanation & Output Generation
  ├── Generate explanation from rule violation
  ├── Enrich with MCP documentation (if available)
  └── Write output.csv

Phase 4: Validation
  ├── Verify CSV format (ID, Bug Line, Explanation)
  └── Check row count and data integrity
```

---

## How the System Remains Deterministic

1. **No randomness**: Every rule is a pure function: `code → Optional[violation]`
2. **Confidence-ranked**: When multiple rules fire, highest confidence wins
3. **Fixed rule order**: Rules execute in defined priority order
4. **Reproducible**: Same input always produces identical output
5. **No external API calls**: No LLM, no cloud services (MCP is local)

---

## How to Extend the Rule Set

### Adding a New Rule

1. **Define the rule** in `code/agents/code_analysis_agent.py`:

```python
def _check_my_new_rule(
    self, lines: List[CodeLine], code: str, sample: SampleRecord
) -> Optional[Tuple[int, str, float]]:
    """Describe what this rule detects."""
    for line in lines:
        if line.stripped.startswith("//"):
            continue
        if "some_pattern" in line.stripped:
            return (
                line.line_number,
                "Explanation of the bug.",
                0.90,  # Confidence: 0.0 to 1.0
            )
    return None
```

2. **Register it** in the `analyze()` method's rule_checks list:

```python
rule_checks = [
    ...existing rules...
    ("my_new_rule", self._check_my_new_rule),
]
```

3. **Add constants** to `config.py` if needed.

### Adding Known Typos

Edit `config.py`:

```python
KNOWN_TYPO_CORRECTIONS = {
    ...existing...
    "wrongName": "correctName",  # Add new typo mapping
}
```

### Adding Valid Getter Functions

```python
VALID_GETTER_FUNCTIONS = {
    ...existing...
    "getNewFunction",  # Add new valid function
}
```

---

## Project Structure

```
BugHunter initial/
├── code/
│   ├── main.py                    # Coordinator & entry point
│   ├── config.py                  # Constants, API patterns, thresholds
│   ├── agents/
│   │   ├── ingestion_agent.py     # CSV parsing
│   │   ├── context_agent.py       # API extraction & query generation
│   │   ├── mcp_retrieval_agent.py # MCP document retrieval
│   │   ├── code_analysis_agent.py # 21 static analysis rules
│   │   └── explanation_agent.py   # Bug report generation
│   ├── models/
│   │   └── data_models.py         # Pydantic-style data contracts
│   └── utils/
│       └── csv_utils.py           # CSV I/O and validation
├── server/
│   ├── mcp_server.py              # FastMCP server (SSE)
│   ├── storage/                   # Vector store data
│   └── embedding_model/           # BAAI/bge-base-en-v1.5
├── samples.csv                    # Input data
├── output.csv                     # Generated output
├── requirements.txt               # Dependencies
└── README.md                      # This file
```

---

## Output Format

```csv
ID,Bug Line,Explanation
2,3,"Invalid vForceRange(35.0 V): not a valid range for AVI64."
4,3,"iClamp argument order error: iClamp(50.0, -50.0) has values exchanged."
13,3,"Invalid function name 'getVesjkctor()' — closest valid: 'getVector()'."
```

Strictly 3 columns: **ID**, **Bug Line**, **Explanation**. No metadata, no logs.

---

## Requirements

```
llama-index==0.14.13
llama-index-embeddings-huggingface
fastmcp
```

Install: `pip install -r requirements.txt`
