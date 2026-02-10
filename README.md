# 🔍 Agentic Bug Hunter

> **Hybrid C++ bug detection for RDI/SmartRDI code.**
> Deterministic rules first. LLM fallback second. MCP validation always.
>
> **"LLM proposes, MCP validates, rules enforce."**

---

## Why Deterministic-First Design?

| Concern | LLM-Only | Our Hybrid Approach |
|---|---|---|
| **Determinism** | Same input → different output | Rules: same input → same output, always |
| **Explainability** | "The model thinks…" | "Rule X fired because condition Y on line Z" |
| **Reliability** | Hallucinations possible | MCP validates all LLM claims |
| **Speed** | API latency on every sample | LLM only invoked when rules don't match |
| **Self-Improvement** | No learning | Validated LLM findings become new rules |

The deterministic rule engine handles **known bug patterns** with 100% reliability. The LLM fallback handles **novel bugs** not yet covered by rules. Over time, the system **learns from LLM discoveries** and converts them into new deterministic rules.

---

## Architecture

<img width="2692" height="1524" alt="image" src="https://github.com/user-attachments/assets/e137eb15-6acb-4d50-b94c-0fc54268102b" />

### Agent Responsibilities

| Agent | Role |
|---|---|
| **IngestionAgent** | Parse evaluation CSV (ID, Context, Code) |
| **ContextInferenceAgent** | Extract RDI API calls, parse lines, generate MCP queries |
| **MCPRetrievalAgent** | Query MCP vector store for relevant documentation |
| **CodeAnalysisAgent** | Apply 21+ static analysis rules to find bugs (PRIMARY) |
| **LLMCodeAnalysisAgent** | Groq OSS-120B fallback for unmatched samples (FALLBACK) |
| **MCPValidatorAgent** | Validate LLM findings against documentation (FIREWALL) |
| **RuleLearningAgent** | Convert validated LLM findings into new deterministic rules |
| **ExplanationAgent** | Generate concise, grounded explanations |

---

## Minimalistic GUI using Tikinter

<img width="1249" height="915" alt="image" src="https://github.com/user-attachments/assets/b0db03e2-335d-4479-86d1-55368396d99b" />


## How the LLM Fallback Works

The LLM is **never used as the primary detection engine**. It only runs when:

1. The deterministic `CodeAnalysisAgent` finds **no matching rule** (`rule_name="no_match"`)
2. The `--no-llm` flag is **not** set
3. `LLM_FALLBACK_ENABLED = True` in config

When invoked:
1. **LLMCodeAnalysisAgent** sends the code to Groq OSS-120B with low temperature (0.15)
2. LLM returns structured JSON: bug line, type, reasoning, confidence, suggested rule
3. **MCPValidatorAgent** checks if MCP documentation supports the claim
4. If validated: the finding replaces the default, and **RuleLearningAgent** persists a new rule
5. If rejected: the default "no_match" result is kept

---

## How MCP Prevents Hallucination

The MCPValidatorAgent acts as a **hallucination firewall**:

1. Extracts keywords from LLM reasoning and bug type
2. Compares against keywords in MCP-retrieved documentation
3. Requires minimum keyword overlap (≥2 shared terms)
4. Only accepts findings with documentation support
5. Exception: very high confidence (≥0.9) findings may pass without docs

This ensures the system **never outputs ungrounded LLM claims**.

---

## How Rule Learning Works

When the LLM discovers a new bug pattern that MCP validates:

1. `RuleLearningAgent` extracts the **suggested rule** from the LLM output
2. Generates a Python function matching the `CodeAnalysisAgent` interface
3. Uses **hash-based deduplication** to prevent duplicate rules
4. Persists to `rules/learned_rules.py`
5. On next run, learned rules are available to the deterministic engine

### Example Learned Rule

```python
@register_rule("missing_initialization")
def _check_missing_initialization(lines, code, sample):
    """
    Detect variables used in RDI chains without prior initialization.
    Detection: variable referenced in rdi\\..*\\(var\\) without prior assignment
    """
    pattern = re.compile(r"rdi\..*\(var\)", re.IGNORECASE)
    for line_obj in lines:
        if pattern.search(line_obj.stripped):
            return (
                line_obj.line_number,
                "Variable used in RDI chain without initialization.",
                0.85,
            )
    return None
```

---

## Safety Guarantees

1. **Deterministic engine ALWAYS runs first** — LLM never overrides
2. **MCP validation is REQUIRED** before accepting LLM output
3. **Learned rules are human-readable** and auditable in `rules/learned_rules.py`
4. **Hash deduplication** prevents rule explosion
5. **Confidence thresholds** filter low-quality LLM suggestions
6. **LLM reasoning is never exposed** directly — only validated, grounded explanations

---

## Bug Detection Rules

The CodeAnalysisAgent implements **21 deterministic rules** in 6 categories:

### Category 1: Lifecycle Rules
| Rule | Description |
|---|---|
| `lifecycle_order` | RDI_BEGIN() must precede RDI_END() |

### Category 2: API Name Validation
| Rule | Description |
|---|---|
| `gibberish_names` | Detect corrupted function names via consonant clusters |
| `known_typos` | Map known wrong names to correct ones |
| `case_sensitivity` | RDI APIs use camelCase |

### Category 3: Argument Validation
| Rule | Description |
|---|---|
| `iclamp_arg_order` | iClamp(low, high) — first ≤ second |
| `vforce_range` | vForce must not exceed vForceRange |
| `invalid_vforce_range_val` | vForceRange must be valid AVI64 range |
| `samples_max` | samples() ≤ 8192 |
| `extra_parameters` | Functions with no params called with args |
| `missing_parameters` | Required params missing |
| `bool_args` | Boolean argument correctness |
| `unit_validation` | Valid RDI units only |

### Category 4: Method Chain Validation
| Rule | Description |
|---|---|
| `duplicate_calls` | Consecutive same method calls |
| `terminal_method` | DC chains end with `.execute()` |
| `chain_order` | Correct method chain ordering |

### Category 5: Consistency Checks
| Rule | Description |
|---|---|
| `pin_consistency` | Setup pins must match retrieval pins |
| `pin_mismatch_in_chain` | Related operations use same pins |
| `invalid_vector_method` | Valid C++ vector methods only |
| `variable_consistency` | Variables must be declared |

### Category 6: Scope Rules
| Rule | Description |
|---|---|
| `enum_validation` | Correct enum for context |
| `scope_violation` | Operations in correct block |

---

## Execution Flow

```bash
# 1. Start MCP server (optional, in separate terminal)
python server/mcp_server.py

# 2. Run full hybrid pipeline
python code/main.py

# 3. Run without MCP (rules-only mode)
python code/main.py --no-mcp

# 4. Run without LLM fallback (pure deterministic)
python code/main.py --no-llm

# 5. Run rules-only (no MCP, no LLM)
python code/main.py --no-mcp --no-llm

# 6. Custom input/output paths
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
  ├── Apply 21+ static analysis rules
  └── Select highest-confidence violation

Phase 2.5: LLM Fallback (if no rule matched)
  ├── Invoke Groq OSS-120B with structured prompt
  ├── Validate LLM finding against MCP docs
  ├── If validated: upgrade the violation + learn new rule
  └── If rejected: keep default

Phase 3: Explanation & Output Generation
  ├── Generate explanation from rule violation
  ├── Enrich with MCP documentation (if available)
  └── Write output.csv

Phase 4: Validation
  ├── Verify CSV format (ID, Bug Line, Explanation)
  └── Check row count and data integrity
```

---

## Project Structure

```
BugHunter initial/
├── code/
│   ├── main.py                       # Coordinator & entry point
│   ├── config.py                     # Constants, API patterns, thresholds
│   ├── agents/
│   │   ├── ingestion_agent.py        # CSV parsing
│   │   ├── context_agent.py          # API extraction & query generation
│   │   ├── mcp_retrieval_agent.py    # MCP document retrieval
│   │   ├── code_analysis_agent.py    # 21 static analysis rules
│   │   ├── explanation_agent.py      # Bug report generation
│   │   ├── llm_analysis_agent.py     # LLM fallback (Groq OSS-120B)
│   │   ├── mcp_validator_agent.py    # MCP-based validation
│   │   └── rule_learning_agent.py    # Auto rule learning
│   ├── models/
│   │   └── data_models.py            # Typed data contracts
│   └── utils/
│       └── csv_utils.py              # CSV I/O and validation
├── rules/
│   └── learned_rules.py              # Auto-learned rules (grows over time)
├── server/
│   ├── mcp_server.py                 # FastMCP server (SSE)
│   ├── storage/                      # Vector store data
│   └── embedding_model/              # BAAI/bge-base-en-v1.5
├── samples.csv                       # Input data
├── output.csv                        # Generated output
├── requirements.txt                  # Dependencies
└── README.md                         # This file
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
groq
```

Install: `pip install -r requirements.txt`

Set the Groq API key: `set GROQ_API_KEY=your_key_here` (Windows) or `export GROQ_API_KEY=your_key_here` (Linux/Mac)
