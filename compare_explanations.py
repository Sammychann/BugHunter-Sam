
import csv
import sys
import io

# Set encoding for Windows console
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

def load_csv(path, key_col='ID'):
    data = {}
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            data[row[key_col]] = row
    return data

ground_truth = load_csv('ground_truth.csv')
generated = load_csv('output_test.csv')

print(f"{'ID':<4} | {'STATUS':<8} | {'GROUND TRUTH (Preview)':<50} | {'GENERATED (Preview)':<50}")
print("-" * 120)

match_count = 0
total = 0

for pid in sorted(ground_truth.keys(), key=lambda x: int(x)):
    total += 1
    gt_exp = ground_truth[pid].get('Explanation', '').strip()
    gen_row = generated.get(pid)
    
    if not gen_row:
        print(f"{pid:<4} | MISSING  | {gt_exp[:48]:<50} | {'(No output)':<50}")
        continue

    gen_exp = gen_row.get('Explanation', '').strip()
    
    # Simple heuristic: exact match is unlikely, check if meaningful
    # Just show them side by side
    status = "OK" 
    if "Potential API misuse" in gen_exp and "BUG:" in gt_exp:
         status = "DEFAULT" # Fallback/No match found
    
    print(f"{pid:<4} | {status:<8} | {gt_exp[:48]:<50} | {gen_exp[:48]:<50}")

print("-" * 120)
print(f"Total processed: {total}")
