
import sys
import os
import csv
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import contextlib
import io

# Ensure code/ is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'code'))

from code.main import run_pipeline
import code.config as config

class BugHunterGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Agentic Bug Hunter GUI")
        self.geometry("1000x700")

        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.selected_files = []
        self.reports = []

        self._create_widgets()

    def _create_widgets(self):
        # ── Top Frame: Controls ────────────────────────────
        control_frame = ttk.Frame(self, padding="10")
        control_frame.pack(fill=tk.X)

        self.btn_load = ttk.Button(control_frame, text="Select C++ Files", command=self.load_files)
        self.btn_load.pack(side=tk.LEFT, padx=5)

        self.btn_run = ttk.Button(control_frame, text="Run Analysis", command=self.start_analysis, state=tk.DISABLED)
        self.btn_run.pack(side=tk.LEFT, padx=5)

        self.lbl_status = ttk.Label(control_frame, text="Ready")
        self.lbl_status.pack(side=tk.LEFT, padx=20)
        
        # Options
        self.var_mcp = tk.BooleanVar(value=True)
        self.chk_mcp = ttk.Checkbutton(control_frame, text="Use MCP", variable=self.var_mcp)
        self.chk_mcp.pack(side=tk.RIGHT, padx=5)

        self.var_llm = tk.BooleanVar(value=True)
        self.chk_llm = ttk.Checkbutton(control_frame, text="Use LLM Fallback", variable=self.var_llm)
        self.chk_llm.pack(side=tk.RIGHT, padx=5)

        # ── Middle Frame: File List ────────────────────────
        file_frame = ttk.LabelFrame(self, text="Selected Files", padding="5")
        file_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=5)
        
        self.lst_files = tk.Listbox(file_frame, height=5)
        self.lst_files.pack(fill=tk.BOTH, expand=True)

        # ── Bottom Frame: Results ──────────────────────────
        result_frame = ttk.LabelFrame(self, text="Detected Bugs", padding="5")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ("ID", "File", "Line", "Rule", "Explanation")
        self.tree = ttk.Treeview(result_frame, columns=columns, show="headings")
        
        self.tree.heading("ID", text="ID")
        self.tree.heading("File", text="File")
        self.tree.heading("Line", text="Line")
        self.tree.heading("Rule", text="Rule Code")
        self.tree.heading("Explanation", text="Explanation")

        self.tree.column("ID", width=40, anchor=tk.CENTER)
        self.tree.column("File", width=150)
        self.tree.column("Line", width=60, anchor=tk.CENTER)
        self.tree.column("Rule", width=150)
        self.tree.column("Explanation", width=500)

        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind select event
        self.tree.bind("<<TreeviewSelect>>", self.on_select_result)

        # ── Detail View ────────────────────────────────────
        detail_frame = ttk.LabelFrame(self, text="Bug Details", padding="5")
        detail_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=5, side=tk.BOTTOM)
        
        self.txt_detail = tk.Text(detail_frame, height=6, wrap=tk.WORD)
        self.txt_detail.pack(fill=tk.BOTH, expand=True)

    def load_files(self):
        filenames = filedialog.askopenfilenames(
            title="Select C++ Files",
            filetypes=[("C++ Files", "*.cpp;*.h;*.hpp;*.c"), ("All Files", "*.*")]
        )
        if filenames:
            self.selected_files = filenames
            self.lst_files.delete(0, tk.END)
            for f in filenames:
                self.lst_files.insert(tk.END, f)
            self.btn_run.config(state=tk.NORMAL)
            self.lbl_status.config(text=f"{len(filenames)} files selected.")

    def start_analysis(self):
        if not self.selected_files:
            return
        
        self.btn_run.config(state=tk.DISABLED)
        self.lbl_status.config(text="Running analysis... (this may take a moment)")
        
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.txt_detail.delete("1.0", tk.END)

        # Run in thread
        threading.Thread(target=self.run_analysis_thread, daemon=True).start()

    def run_analysis_thread(self):
        try:
            # 1. Create temp input CSV
            temp_input = "gui_temp_input.csv"
            temp_output = "gui_temp_output.csv"
            
            with open(temp_input, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Code", "Context"])
                
                for idx, filepath in enumerate(self.selected_files, 1):
                    try:
                        with open(filepath, 'r', encoding='utf-8') as src:
                            code_content = src.read()
                        # Use filename as context
                        context_str = f"File: {os.path.basename(filepath)}"
                        writer.writerow([idx, code_content, context_str])
                    except Exception as e:
                        print(f"Error reading {filepath}: {e}")

            # 2. Configure pipeline
            use_mcp = self.var_mcp.get()
            use_llm = self.var_llm.get()
            
            # Capture stdout to redirect to console/log if needed (optional)
            # For now, let it print to console
            
            # 3. Run Pipeline
            # We must import run_pipeline here or use the one imported globally
            # But specific flags need to be set in config if not passed
            
            # run_pipeline arguments: input_path, output_path, use_mcp, use_llm
            reports = run_pipeline(
                input_path=temp_input,
                output_path=temp_output,
                use_mcp=use_mcp,
                use_llm=use_llm
            )

            # 4. Schedule UI update
            self.after(0, self.update_results, reports)

        except Exception as e:
            self.after(0, self.show_error, str(e))

    def update_results(self, reports):
        self.reports = reports
        for r in reports:
            # Match ID to filename
            # Note: IDs in reports correspond to the 1-based index in selected_files
            try:
                filename = os.path.basename(self.selected_files[r.id - 1])
            except IndexError:
                filename = "Unknown"
            
            # We don't have rule name directly in BugReport (it's in violations dict in main.py)
            # But the explanation usually starts with "RuleName: ..." or similar if we formatted it
            # Actually, main.py prints the rule but returns BugReport object which only has ID, Line, Explanation.
            # The Shim in main.py returns list[BugReport].
            # BugReport doesn't have Rule Name field. 
            # I might need to Parse explanation or just show explanation.
            
            rule_name = "See Explanation"
            if ":" in r.explanation:
                rule_name = r.explanation.split(":")[0] # heuristic

            self.tree.insert("", tk.END, values=(r.id, filename, r.bug_line, rule_name, r.explanation))
        
        self.lbl_status.config(text=f"Analysis complete. Found {len(reports)} issues.")
        self.btn_run.config(state=tk.NORMAL)
        messagebox.showinfo("Complete", f"Analysis finished.\nFound {len(reports)} potential bugs.")

    def show_error(self, msg):
        self.lbl_status.config(text="Error occurred.")
        self.btn_run.config(state=tk.NORMAL)
        messagebox.showerror("Error", msg)

    def on_select_result(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            item = self.tree.item(selected_item)
            values = item['values']
            # Explanation is index 4
            explanation = values[4]
            self.txt_detail.delete("1.0", tk.END)
            self.txt_detail.insert(tk.END, explanation)

if __name__ == "__main__":
    app = BugHunterGUI()
    app.mainloop()
