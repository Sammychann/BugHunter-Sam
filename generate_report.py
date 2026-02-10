
import csv

def load_csv(path, key_col='ID'):
    data = {}
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            data[row[key_col]] = row
    return data

ground_truth = load_csv('ground_truth.csv')
generated = load_csv('output_test.csv')

with open('comparison_report.md', 'w', encoding='utf-8') as f:
    f.write("# Comparison Report: Ground Truth vs Generated Explanations\n\n")
    f.write("| ID | Status | Ground Truth Explanation | Generated Explanation |\n")
    f.write("|---|---|---|---|\n")

    for pid in sorted(ground_truth.keys(), key=lambda x: int(x)):
        gt_exp = ground_truth[pid].get('Explanation', '').strip().replace('\n', '<br>')
        gen_row = generated.get(pid)
        
        if not gen_row:
            f.write(f"| {pid} | MISSING | {gt_exp} | *(No output)* |\n")
            continue

        gen_exp = gen_row.get('Explanation', '').strip().replace('\n', '<br>')
        
        status = "✅ Detected"
        if "Potential API misuse" in gen_exp and "BUG:" in gt_exp:
             status = "⚠️ Default"
        
        f.write(f"| {pid} | {status} | {gt_exp} | {gen_exp} |\n")

print("Report generated: comparison_report.md")
