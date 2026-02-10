"""Evaluate pipeline output against expected ground truth."""
import csv
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Expected ground truth - derived from samples2.csv
# Format: {ID: (expected_bug_line, bug_category)}
expected = {
    101: (1,  'enum_validation'),
    102: (2,  'terminal_method'),
    103: (1,  'iclamp_arg_order'),
    104: (2,  'terminal_method'),
    105: (4,  'lifecycle_missing'),
    106: (1,  'missing_parameters'),
    107: (1,  'case_sensitivity'),
    108: (3,  'chain_order'),
    109: (1,  'pin_consistency'),
    110: (1,  'extra_parameters'),
    111: (1,  'vforce_range'),
    112: (1,  'terminal_method'),
    113: (1,  'known_typos'),
    114: (3,  'scope_violation'),
    115: (1,  'bool_args'),
    116: (1,  'samples_max'),
    117: (1,  'known_typos'),
    118: (1,  'novel_readMode'),
    119: (1,  'lifecycle_missing'),
    120: (1,  'variable_consistency'),
}

# Read actual output
actual = {}
with open('output2.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        sid = int(row['ID'])
        actual[sid] = (int(row['Bug Line']), row['Explanation'])

# Compare
print('=' * 90)
print('  PERFORMANCE EVALUATION: samples2.csv -> output2.csv')
print('=' * 90)
print()

correct_line = 0
detected = 0
total = len(expected)
no_match_ids = []
llm_detected_ids = []

for sid in sorted(expected.keys()):
    exp_line, category = expected[sid]
    if sid in actual:
        act_line, explanation = actual[sid]
        line_ok = act_line == exp_line
        if line_ok:
            correct_line += 1

        is_default = 'Potential API misuse detected in code snippet.' == explanation.strip()
        is_llm = 'Impact: Potential API misuse detected.' in explanation
        
        if is_default:
            no_match_ids.append(sid)
            source = 'NO_MATCH'
        elif is_llm:
            llm_detected_ids.append(sid)
            detected += 1
            source = 'LLM'
        else:
            detected += 1
            source = 'RULES'

        status = 'OK' if line_ok else 'WRONG'
        shortexp = explanation[:55].replace('\n', ' ')
        print(f'  ID {sid:>3} | exp={exp_line} act={act_line} | {status:>5} | {source:>8} | {category:<22} | {shortexp}...')
    else:
        print(f'  ID {sid:>3} | MISSING FROM OUTPUT')

print()
print('=' * 90)
print('  RESULTS SUMMARY')
print('=' * 90)
print(f'  Total test samples:     {total}')
print(f'  Correct bug line:       {correct_line} / {total}  ({correct_line/total*100:.0f}%)')
print(f'  Bugs detected (total):  {detected} / {total}  ({detected/total*100:.0f}%)')
print(f'    - By deterministic rules: {detected - len(llm_detected_ids)}')
print(f'    - By LLM fallback:        {len(llm_detected_ids)} {llm_detected_ids}')
print(f'  No detection (default):     {len(no_match_ids)} {no_match_ids}')
print('=' * 90)
