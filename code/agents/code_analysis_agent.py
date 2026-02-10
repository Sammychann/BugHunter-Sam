"""
============================================================
PHASE 2: Code Analysis Agent — Rule-Based Static Analysis
============================================================
Responsibility:
    Apply deterministic validation rules to C++ RDI/SmartRDI
    code to identify the exact buggy line number.

Input:  SampleRecord + InferredContext + List[MCPResult]
Output: RuleViolation (line number + explanation)

Design Notes:
    - 15+ static analysis rules organized by category
    - Rules are applied in priority order
    - First high-confidence violation is selected
    - Fully deterministic — no ML or LLM involved
    - Each rule returns (line_number, explanation) or None

Rule Categories:
    1. Lifecycle ordering (RDI_BEGIN/END)
    2. API name validation (typos, gibberish, casing)
    3. Argument validation (order, values, counts, units)
    4. Method chain validation (terminal methods, ordering)
    5. Consistency checks (pin names, variables)
    6. Scope rules (operations in wrong block)
============================================================
"""

import re
import logging
from typing import List, Optional, Tuple
from difflib import SequenceMatcher

from models.data_models import (
    SampleRecord, InferredContext, MCPResult,
    RuleViolation, CodeLine,
)
import config

logger = logging.getLogger(__name__)


class CodeAnalysisAgent:
    """
    Agent #4: Code Analysis (Rule-Based Bug Detection)
    Applies deterministic static analysis rules to detect
    RDI/SmartRDI API misuse in C++ code snippets.
    """

    def __init__(self):
        logger.info("CodeAnalysisAgent initialized with rule engine.")

    def analyze(
        self,
        sample: SampleRecord,
        context: InferredContext,
        mcp_results: List[MCPResult],
    ) -> RuleViolation:
        """
        Run all rules against the code and return the top violation.

        Rules are applied in priority order. The first high-confidence
        match is returned as the primary bug.

        Args:
            sample: Raw sample record
            context: Inferred context with parsed lines
            mcp_results: MCP documentation (for context-aware rules)

        Returns:
            RuleViolation with the detected bug line and explanation
        """
        lines = context.code_lines
        code = sample.code

        # ── Apply rules in priority order ──────────────────
        # Higher priority rules are more specific and reliable
        rule_checks = [
            ("lifecycle_order",     self._check_lifecycle_order),
            ("gibberish_names",     self._check_gibberish_names),
            ("known_typos",         self._check_known_typos),
            ("case_sensitivity",    self._check_case_sensitivity),
            ("unit_validation",     self._check_unit_validation),
            ("iclamp_arg_order",    self._check_iclamp_arguments),
            ("vforce_range",        self._check_vforce_range),
            ("invalid_vforce_range_val", self._check_vforce_range_value),
            ("samples_max",         self._check_samples_max),
            ("extra_parameters",    self._check_extra_parameters),
            ("missing_parameters",  self._check_missing_parameters),
            ("bool_args",           self._check_boolean_arguments),
            ("duplicate_calls",     self._check_duplicate_calls),
            ("terminal_method",     self._check_terminal_methods),
            ("chain_order",         self._check_chain_order),
            ("enum_validation",     self._check_enum_values),
            ("pin_consistency",     self._check_pin_consistency),
            ("invalid_vector_method", self._check_vector_methods),
            ("variable_consistency", self._check_variable_consistency),
            ("scope_violation",     self._check_scope_violations),
            ("pin_mismatch_in_chain", self._check_pin_mismatch_in_chain),
        ]

        violations: List[RuleViolation] = []

        for rule_name, check_fn in rule_checks:
            try:
                result = check_fn(lines, code, sample)
                if result:
                    line_num, explanation, confidence = result
                    violation = RuleViolation(
                        rule_name=rule_name,
                        line_number=line_num,
                        line_content=self._get_line(lines, line_num),
                        explanation=explanation,
                        confidence=confidence,
                    )
                    violations.append(violation)
                    logger.debug(f"  Rule '{rule_name}' fired: line {line_num} "
                                  f"(confidence={confidence:.2f})")
            except Exception as e:
                logger.debug(f"  Rule '{rule_name}' error: {e}")

        # ── Select highest-confidence violation ────────────
        if violations:
            violations.sort(key=lambda v: v.confidence, reverse=True)
            best = violations[0]
            logger.info(f"  ID={sample.id}: Bug on line {best.line_number} "
                         f"(rule={best.rule_name}, conf={best.confidence:.2f})")
            return best

        # ── Fallback: report line 1 if no rule matched ────
        logger.warning(f"  ID={sample.id}: No rule matched, defaulting to line 1")
        return RuleViolation(
            rule_name="no_match",
            line_number=1,
            line_content=self._get_line(lines, 1),
            explanation="Potential API misuse detected in code snippet.",
            confidence=0.1,
        )

    # ══════════════════════════════════════════════════════
    # RULE IMPLEMENTATIONS
    # ══════════════════════════════════════════════════════

    def _check_lifecycle_order(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 1: RDI_BEGIN() must appear before RDI_END().
        Detects inverted lifecycle ordering.
        """
        begin_line = None
        end_line = None

        for line in lines:
            if "RDI_BEGIN()" in line.stripped:
                if begin_line is None:
                    begin_line = line.line_number
            if "RDI_END()" in line.stripped:
                if end_line is None:
                    end_line = line.line_number

        if end_line is not None and begin_line is not None and end_line < begin_line:
            return (
                end_line,
                "Lifecycle order error: RDI_END() appears before RDI_BEGIN(), "
                "inverting the intended session/transaction scope. "
                "RDI_BEGIN() must be called before any RDI operations, "
                "followed by RDI_END() to close the scope.",
                0.98,
            )
        return None

    def _check_gibberish_names(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 2: Detect function names that are gibberish
        (random characters inserted into valid API names).
        Uses edit distance against known valid function names.
        """
        getter_pattern = re.compile(r'\.get(\w+)\(')

        for line in lines:
            if line.stripped.startswith("//"):
                continue
            matches = getter_pattern.findall(line.stripped)
            for match in matches:
                full_name = f"get{match}"
                if full_name not in config.VALID_GETTER_FUNCTIONS:
                    # Find closest valid getter for the explanation
                    best_match, best_ratio = self._find_closest_match(
                        full_name, config.VALID_GETTER_FUNCTIONS
                    )
                    # Check for gibberish via consonant clusters
                    has_gibberish = self._has_gibberish_chars(match)
                    if has_gibberish:
                        return (
                            line.line_number,
                            f"Invalid function name '{full_name}()' — "
                            f"this appears to be a corrupted API name. "
                            f"The closest valid function is '{best_match}()'.",
                            0.96,
                        )
                    # Any unknown getter is flagged
                    if best_ratio < 1.0 and best_ratio > 0.2:
                        return (
                            line.line_number,
                            f"Invalid function name '{full_name}()' — "
                            f"not a recognized RDI getter. "
                            f"The closest valid function is '{best_match}()'.",
                            0.92,
                        )

        # Also check for gibberish in rdi.id().xxx() chains
        id_method_pattern = re.compile(r'rdi\.id\([^)]*\)\.(\w+)\(')
        for line in lines:
            if line.stripped.startswith("//"):
                continue
            matches = id_method_pattern.findall(line.stripped)
            for method in matches:
                if method.startswith("get"):
                    continue  # Already checked above
                # Check against all known methods
                all_known = config.VALID_RDI_METHODS | config.VALID_GETTER_FUNCTIONS
                if method not in all_known:
                    best_match, best_ratio = self._find_closest_match(
                        method, all_known
                    )
                    if best_ratio < 0.85:
                        return (
                            line.line_number,
                            f"Invalid function name '{method}()' — "
                            f"this is not a recognized RDI API method. "
                            f"The closest valid function is '{best_match}()'.",
                            0.95,
                        )
        return None

    def _check_known_typos(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 3: Check for known function name typos.
        Uses the KNOWN_TYPO_CORRECTIONS mapping from config.
        """
        for line in lines:
            if line.stripped.startswith("//"):
                continue
            for wrong, correct in config.KNOWN_TYPO_CORRECTIONS.items():
                # Check for the wrong name as a method call
                pattern = re.compile(rf'\.{re.escape(wrong)}\s*\(')
                if pattern.search(line.stripped):
                    return (
                        line.line_number,
                        f"Incorrect function name: '.{wrong}()' should be "
                        f"'.{correct}()'. This is a known API naming error.",
                        0.93,
                    )
                # Also check as rdi.xxx() root call
                pattern2 = re.compile(rf'rdi\.{re.escape(wrong)}\s*\(')
                if pattern2.search(line.stripped):
                    return (
                        line.line_number,
                        f"Incorrect function name: 'rdi.{wrong}()' should be "
                        f"'rdi.{correct}()'. This is a known API naming error.",
                        0.93,
                    )
        return None

    def _check_case_sensitivity(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 4: RDI APIs are case-sensitive.
        Detect lowercase variants of known APIs.
        """
        case_sensitive_apis = {
            "imeas": "iMeas", "vmeas": "vMeas",
            "imeasrange": "iMeasRange", "vmeasrange": "vMeasRange",
            "iclamp": "iClamp", "vclamp": "vClamp",
            "vforce": "vForce", "iforce": "iForce",
            "vforcerange": "vForceRange", "iforcerange": "iForceRange",
        }

        for line in lines:
            if line.stripped.startswith("//"):
                continue
            for wrong_case, correct_case in case_sensitive_apis.items():
                # Match exact lowercase version (not the already-correct one)
                pattern = re.compile(rf'\.{re.escape(wrong_case)}\s*\(')
                if pattern.search(line.stripped):
                    # Verify it's not already the correct case
                    correct_pattern = re.compile(rf'\.{re.escape(correct_case)}\s*\(')
                    if not correct_pattern.search(line.stripped):
                        return (
                            line.line_number,
                            f"Case sensitivity error: '.{wrong_case}()' should be "
                            f"'.{correct_case}()'. RDI APIs use camelCase naming.",
                            0.92,
                        )
        return None

    def _check_unit_validation(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 5: Validate measurement units.
        Detect invalid units like 'mAh' instead of 'mA'.
        """
        for wrong_unit, correct_unit in config.INVALID_UNITS.items():
            pattern = re.compile(rf'\b\d+\s+{re.escape(wrong_unit)}\b')
            for line in lines:
                if line.stripped.startswith("//"):
                    continue
                if pattern.search(line.stripped):
                    return (
                        line.line_number,
                        f"Invalid unit: '{wrong_unit}' is not a valid RDI unit. "
                        f"The correct unit is '{correct_unit}'.",
                        0.91,
                    )
        return None

    def _check_iclamp_arguments(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 6: iClamp(low, high) — first argument must be ≤ second.
        Detects swapped clamp values.
        """
        iclamp_pattern = re.compile(
            r'\.iClamp\s*\(\s*(-?[\d.]+)\s*\w*\s*,\s*(-?[\d.]+)\s*\w*\s*\)'
        )
        for line in lines:
            if line.stripped.startswith("//"):
                continue
            match = iclamp_pattern.search(line.stripped)
            if match:
                val1 = float(match.group(1))
                val2 = float(match.group(2))
                if val1 > val2:
                    return (
                        line.line_number,
                        f"iClamp argument order error: iClamp({val1}, {val2}) "
                        f"has low and high values exchanged. First argument "
                        f"should be the low clamp, second should be high. "
                        f"Correct: iClamp({val2}, {val1}).",
                        0.97,
                    )
        return None

    def _check_vforce_range(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 7: vForce value must not exceed vForceRange value.
        The programmed force must match the selected range.
        """
        # Extract vForce and vForceRange from the same line or chain
        vforce_pattern = re.compile(r'\.vForce\s*\(\s*(-?[\d.]+)\s*\w*\s*\)')
        vrange_pattern = re.compile(r'\.vForceRange\s*\(\s*(-?[\d.]+)\s*\w*\s*\)')

        for line in lines:
            if line.stripped.startswith("//"):
                continue
            vf_match = vforce_pattern.search(line.stripped)
            vr_match = vrange_pattern.search(line.stripped)

            if vf_match and vr_match:
                vforce_val = float(vf_match.group(1))
                vrange_val = float(vr_match.group(1))
                if vforce_val > vrange_val:
                    return (
                        line.line_number,
                        f"Range overflow: vForce({vforce_val} V) exceeds "
                        f"vForceRange({vrange_val} V). The programmed force "
                        f"value must always match the selected range to avoid "
                        f"range overflow warnings.",
                        0.96,
                    )
        return None

    def _check_vforce_range_value(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 8: vForceRange must be a valid range for AVI64.
        Valid ranges: 2, 5, 10, 15, 20, 30 V.
        """
        vrange_pattern = re.compile(r'\.vForceRange\s*\(\s*(-?[\d.]+)\s*V?\s*\)')

        for line in lines:
            if line.stripped.startswith("//"):
                continue
            match = vrange_pattern.search(line.stripped)
            if match:
                val = float(match.group(1))
                if val not in config.VALID_VFORCE_RANGES and val > 0:
                    valid_str = ", ".join(str(v) for v in sorted(config.VALID_VFORCE_RANGES))
                    return (
                        line.line_number,
                        f"Invalid vForceRange({val} V): this is not a valid "
                        f"range for AVI64. Valid ranges are: {valid_str} V.",
                        0.90,
                    )
        return None

    def _check_samples_max(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 9: samples() value must not exceed 8192.
        """
        samples_pattern = re.compile(r'\.samples\s*\(\s*(\d+)\s*\)')

        for line in lines:
            if line.stripped.startswith("//"):
                continue
            match = samples_pattern.search(line.stripped)
            if match:
                val = int(match.group(1))
                if val > config.MAX_DIGCAP_SAMPLES:
                    return (
                        line.line_number,
                        f"Sample count {val} exceeds maximum allowed "
                        f"value of {config.MAX_DIGCAP_SAMPLES}.",
                        0.90,
                    )
        return None

    def _check_extra_parameters(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 10: Detect functions called with parameters that take none.
        e.g., readTempThresh() takes no arguments.
        """
        no_param_functions = {
            "readTempThresh": "readTempThresh() takes no parameters",
        }

        for line in lines:
            if line.stripped.startswith("//"):
                continue
            for func, msg in no_param_functions.items():
                pattern = re.compile(
                    rf'\.{re.escape(func)}\s*\(\s*[^)]+\s*\)'
                )
                empty_pattern = re.compile(
                    rf'\.{re.escape(func)}\s*\(\s*\)'
                )
                if pattern.search(line.stripped) and not empty_pattern.search(line.stripped):
                    return (
                        line.line_number,
                        f"Extra parameter: {msg}. "
                        f"Remove the argument to fix this API call.",
                        0.92,
                    )
        return None

    def _check_missing_parameters(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 11: Detect functions called without required parameters.
        e.g., getAlarmValue() requires a pin name parameter.
        """
        required_param_functions = {
            "getAlarmValue": "getAlarmValue() requires a pin name string parameter",
        }

        for line in lines:
            if line.stripped.startswith("//"):
                continue
            for func, msg in required_param_functions.items():
                empty_pattern = re.compile(
                    rf'\.{re.escape(func)}\s*\(\s*\)'
                )
                if empty_pattern.search(line.stripped):
                    return (
                        line.line_number,
                        f"Missing parameter: {msg}.",
                        0.92,
                    )
        return None

    def _check_boolean_arguments(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 12: Detect incorrect boolean arguments.
        e.g., digCapBurstSiteUpload(false) should be true.
        """
        bool_rules = {
            "digCapBurstSiteUpload": ("false", "true",
                "digCapBurstSiteUpload should be set to true for uploads"),
        }

        for line in lines:
            if line.stripped.startswith("//"):
                continue
            for func, (wrong_val, correct_val, msg) in bool_rules.items():
                pattern = re.compile(
                    rf'{re.escape(func)}\s*\(\s*{re.escape(wrong_val)}\s*\)'
                )
                if pattern.search(line.stripped):
                    return (
                        line.line_number,
                        f"{msg}. Currently set to {wrong_val}, "
                        f"should be {correct_val}.",
                        0.90,
                    )
        return None

    def _check_duplicate_calls(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 13: Detect duplicate consecutive method calls.
        e.g., .end().end() or .burst().burst()
        """
        dup_pattern = re.compile(r'\.(\w+)\(\)\.(\1)\(\)')

        for line in lines:
            if line.stripped.startswith("//"):
                continue
            match = dup_pattern.search(line.stripped)
            if match:
                method = match.group(1)
                return (
                    line.line_number,
                    f"Duplicate method call: .{method}().{method}() — "
                    f"the same function is called twice consecutively. "
                    f"Remove the duplicate .{method}() call.",
                    0.93,
                )

        # Also check for .burst() appearing as terminal on multiple lines
        burst_terminal_lines = []
        for line in lines:
            if line.stripped.startswith("//"):
                continue
            if re.search(r'\.burst\(\)\s*;', line.stripped):
                burst_terminal_lines.append(line.line_number)
        if len(burst_terminal_lines) >= 2:
            return (
                burst_terminal_lines[0],
                "Multiple lines end with .burst() instead of .execute(). "
                "In most RDI chains, the terminal method should be .execute().",
                0.80,
            )

        return None

    def _check_terminal_methods(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 14: DC/func measurement chains should end with .execute().
        Detect .read(), .write(), or .burst() used instead.
        """
        # Patterns for rdi chains that should end with .execute()
        wrong_terminals = {
            ".read()": "execute()",
            ".write()": "execute()",
        }

        for line in lines:
            if line.stripped.startswith("//"):
                continue
            for wrong, correct in wrong_terminals.items():
                if wrong in line.stripped:
                    # Check it's part of an rdi chain
                    if "rdi." in line.stripped or "rdi." in code:
                        # Check if this is in a dc/func context
                        context_check = self._is_in_rdi_chain(lines, line.line_number)
                        if context_check:
                            return (
                                line.line_number,
                                f"Wrong terminal method: '{wrong.strip('.')}' should be "
                                f"'{correct}' in this RDI measurement chain. "
                                f"DC and func operations require .execute() to complete.",
                                0.88,
                            )
        return None

    def _check_chain_order(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 15: Method chain ordering validation.
        e.g., rdi.burstUpload.smartVec() should be rdi.smartVec().burstUpload()
        """
        for line in lines:
            if line.stripped.startswith("//"):
                continue
            # Check for rdi.burstUpload.smartVec (wrong order)
            if re.search(r'rdi\.burstUpload\.smartVec', line.stripped):
                return (
                    line.line_number,
                    "Incorrect chain order: 'rdi.burstUpload.smartVec()' "
                    "should be 'rdi.smartVec().burstUpload()'. "
                    "burstUpload() is a method of smartVec, not the other way around.",
                    0.95,
                )
        return None

    def _check_enum_values(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 16: Validate enum values in context.
        e.g., vecEditMode should use TA::VTT when copyLabel() is used.
        """
        has_copy_label = "copyLabel" in code

        if has_copy_label:
            for line in lines:
                if line.stripped.startswith("//"):
                    continue
                if "vecEditMode" in line.stripped and "TA::VECD" in line.stripped:
                    return (
                        line.line_number,
                        "Wrong vector edit mode: when copyLabel() is used, "
                        "vecEditMode must be TA::VTT, not TA::VECD. "
                        "VTT mode is required for label-based vector editing.",
                        0.94,
                    )
        return None

    def _check_pin_consistency(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 17: Pin names used in setup must match those in retrieval.
        Detects D0 (digit) vs DO (letter) type mismatches.
        """
        # Find pins used in capture/setup operations
        setup_pins = {}
        retrieval_pins = {}

        pin_in_setup = re.compile(r'(?:digCap|dc|func|emap|smartVec)\([^)]*\).*?\.pin\(\s*"([^"]+)"\s*\)')
        pin_in_get = re.compile(r'(?:getVector|getReadBit|getReadData)\(\s*"([^"]+)"\s*\)')

        for line in lines:
            if line.stripped.startswith("//"):
                continue
            setup_match = pin_in_setup.search(line.stripped)
            if setup_match:
                setup_pins[setup_match.group(1)] = line.line_number

            get_match = pin_in_get.search(line.stripped)
            if get_match:
                retrieval_pins[get_match.group(1)] = line.line_number

        # Check for mismatches between setup and retrieval pins
        for setup_pin, setup_line in setup_pins.items():
            for ret_pin, ret_line in retrieval_pins.items():
                if setup_pin != ret_pin and self._is_similar_pin(setup_pin, ret_pin):
                    return (
                        setup_line,
                        f"Pin name mismatch: pin '{setup_pin}' in setup (line {setup_line}) "
                        f"does not match '{ret_pin}' in retrieval (line {ret_line}). "
                        f"These look like they should be the same pin "
                        f"(possible typo: '{setup_pin}' vs '{ret_pin}').",
                        0.91,
                    )
        return None

    def _check_vector_methods(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 18: Validate methods called on vector<string>.
        e.g., push_forward is not valid, should be push_back.
        """
        # Detect vector declarations
        vector_vars = set()
        vec_decl = re.compile(r'vector\s*<\s*string\s*>\s+(\w+)')
        for line in lines:
            match = vec_decl.search(line.stripped)
            if match:
                vector_vars.add(match.group(1))

        if not vector_vars:
            return None

        # Check for invalid methods on vector variables
        for line in lines:
            if line.stripped.startswith("//"):
                continue
            for var in vector_vars:
                # Check for .burst() on vector (should be .clear())
                if re.search(rf'{re.escape(var)}\.burst\s*\(', line.stripped):
                    return (
                        line.line_number,
                        f"Invalid method: '{var}.burst()' is not a valid "
                        f"vector<string> method. Use '{var}.clear()' instead.",
                        0.93,
                    )
                # Check for push_forward (should be push_back)
                if re.search(rf'{re.escape(var)}\.push_forward\s*\(', line.stripped):
                    return (
                        line.line_number,
                        f"Invalid method: '{var}.push_forward()' does not exist. "
                        f"Use '{var}.push_back()' instead.",
                        0.93,
                    )
        return None

    def _check_variable_consistency(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 19: Variables used must be properly declared/initialized.
        Detect use of undeclared variables or wrong variable names.
        """
        # Find declared variables (simple declaration detection)
        declared_vars = set()
        decl_pattern = re.compile(
            r'(?:vector\s*<[^>]+>|int|double|float|string|ARRAY_\w+|const\s+\w+&?)\s+(\w+)'
        )
        for line in lines:
            for match in decl_pattern.finditer(line.stripped):
                declared_vars.add(match.group(1))

        if not declared_vars:
            return None

        # Check for variables that look like typos of declared vars
        var_usage = re.compile(r'\b(vec_\w+|ary_\w+)\b')
        for line in lines:
            if line.stripped.startswith("//"):
                continue
            for match in var_usage.finditer(line.stripped):
                used_var = match.group(1)
                if used_var not in declared_vars:
                    # Check if it's similar to a declared variable
                    for decl in declared_vars:
                        ratio = SequenceMatcher(None, used_var, decl).ratio()
                        if 0.5 < ratio < 1.0:
                            return (
                                line.line_number,
                                f"Undeclared variable: '{used_var}' is used but "
                                f"only '{decl}' was declared. This appears to be "
                                f"a variable name mismatch.",
                                0.88,
                            )
        return None

    def _check_scope_violations(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 20: Detect operations in wrong scope.
        e.g., retrievePmuxPinStatus should be after RDI_END, not inside
        RDI_BEGIN/RDI_END block.
        """
        in_rdi_block = False
        rdi_end_line = None

        for line in lines:
            if "RDI_BEGIN()" in line.stripped:
                in_rdi_block = True
            elif "RDI_END()" in line.stripped:
                in_rdi_block = False
                rdi_end_line = line.line_number

            if in_rdi_block and "retrievePmuxPinStatus" in line.stripped:
                return (
                    line.line_number,
                    "Scope violation: retrievePmuxPinStatus() should be called "
                    "after RDI_END(), not inside the RDI_BEGIN/RDI_END block. "
                    "Status retrieval requires the execution block to complete first.",
                    0.89,
                )
        return None

    def _check_pin_mismatch_in_chain(
        self, lines: List[CodeLine], code: str, sample: SampleRecord
    ) -> Optional[Tuple[int, str, float]]:
        """
        Rule 21: Detect pin name changes within a related chain.
        e.g., pin("DPS_1,DPS_2") in setup but pin("DPS_0,DPS_1") in measurement.
        """
        pin_pattern = re.compile(r'\.pin\(\s*"([^"]+)"\s*\)')
        pin_usages = []

        for line in lines:
            if line.stripped.startswith("//"):
                continue
            match = pin_pattern.search(line.stripped)
            if match:
                pin_usages.append((line.line_number, match.group(1)))

        # Check for pin groups that partially overlap but aren't identical
        if len(pin_usages) >= 2:
            for i in range(len(pin_usages)):
                for j in range(i + 1, len(pin_usages)):
                    pins_i = set(pin_usages[i][1].split(","))
                    pins_j = set(pin_usages[j][1].split(","))
                    # If they overlap but aren't identical, it's suspicious
                    overlap = pins_i & pins_j
                    if overlap and pins_i != pins_j and len(pins_i) == len(pins_j):
                        return (
                            pin_usages[j][0],
                            f"Pin list mismatch: '{pin_usages[j][1]}' differs from "
                            f"'{pin_usages[i][1]}' used earlier. The pin configuration "
                            f"should be consistent across related operations.",
                            0.85,
                        )
        return None

    # ══════════════════════════════════════════════════════
    # HELPER METHODS
    # ══════════════════════════════════════════════════════

    def _get_line(self, lines: List[CodeLine], line_num: int) -> str:
        """Get the content of a specific line number."""
        for line in lines:
            if line.line_number == line_num:
                return line.stripped
        return ""

    def _find_closest_match(self, name: str, valid_names: set) -> Tuple[str, float]:
        """Find the closest matching name using SequenceMatcher."""
        best_match = ""
        best_ratio = 0.0
        for valid in valid_names:
            ratio = SequenceMatcher(None, name.lower(), valid.lower()).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_match = valid
        return best_match, best_ratio

    def _is_similar_pin(self, pin1: str, pin2: str) -> bool:
        """Check if two pin names are confusingly similar (e.g., D0 vs DO)."""
        if len(pin1) != len(pin2):
            return False
        diffs = sum(1 for a, b in zip(pin1, pin2) if a != b)
        return diffs == 1  # Exactly one character different

    def _has_gibberish_chars(self, name: str) -> bool:
        """
        Detect gibberish in a function name by looking for unusual
        consonant clusters (3+ consecutive consonants like 'sjk', 'lkh').
        Real API names follow CamelCase English word boundaries.
        """
        consonants = set("bcdfghjklmnpqrstvwxyz")
        name_lower = name.lower()
        streak = 0
        for ch in name_lower:
            if ch in consonants:
                streak += 1
                if streak >= 3:
                    return True
            else:
                streak = 0
        return False

    def _is_in_rdi_chain(self, lines: List[CodeLine], target_line: int) -> bool:
        """Check if a line is part of an rdi API chain."""
        for line in lines:
            if line.line_number <= target_line and line.line_number >= target_line - 5:
                if "rdi." in line.content:
                    return True
        return False
