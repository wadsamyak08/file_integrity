

import os
import hashlib
import json
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

BASELINE_FILE = "fim_baseline.json"
# ... rest of the code continues normally

class FileIntegrityMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Monitor (FIM)")
        self.root.geometry("950x650")
        self.root.resizable(True, True)
        self.root.configure(bg="#1e1e2e")

        # Application State
        self.monitored_paths = []  # List of files/folders configured by user
        self.baseline = {}          # Map of filepath -> SHA-256 hash
        
        self.load_state()
        self.setup_styles()
        self.create_widgets()
        self.refresh_monitored_list()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Theme Colors
        self.bg_color = "#1e1e2e"
        self.fg_color = "#cdd6f4"
        self.accent_color = "#89b4fa"
        self.green = "#a6e3a1"
        self.yellow = "#f9e2af"
        self.red = "#f38ba8"
        self.surface = "#313244"

        self.style.configure("Main.TFrame", background=self.bg_color)
        self.style.configure("Title.TLabel",
                             background=self.bg_color,
                             foreground=self.accent_color,
                             font=("Segoe UI", 18, "bold"))

        self.style.configure("Standard.TLabel",
                             background=self.bg_color,
                             foreground=self.fg_color,
                             font=("Segoe UI", 10))

        # Button configs
        self.style.configure("Primary.TButton",
                             background=self.accent_color,
                             foreground="#1e1e2e",
                             font=("Segoe UI", 10, "bold"),
                             padding=(12, 6))
        self.style.map("Primary.TButton", background=[("active", "#74c7ec")])

        self.style.configure("Secondary.TButton",
                             background="#45475a",
                             foreground=self.fg_color,
                             font=("Segoe UI", 9),
                             padding=(8, 4))
        self.style.map("Secondary.TButton", background=[("active", "#585b70")])

        # Treeview styling
        self.style.configure("FIM.Treeview",
                             background=self.surface,
                             foreground=self.fg_color,
                             fieldbackground=self.surface,
                             font=("Segoe UI", 9),
                             rowheight=25)

        self.style.configure("FIM.Treeview.Heading",
                             background="#45475a",
                             foreground=self.fg_color,
                             font=("Segoe UI", 9, "bold"))

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, style="Main.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # ── Header ──
        header_frame = ttk.Frame(main_frame, style="Main.TFrame")
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(header_frame, text="🛡️ File Integrity Monitor", style="Title.TLabel").pack(side=tk.LEFT)
        ttk.Label(header_frame, text="Detect unauthorized modifications, deletions, or additions", 
                  style="Standard.TLabel").pack(side=tk.LEFT, padx=(15, 0), pady=(8, 0))

        # ── Left / Right Split Frame ──
        split_frame = ttk.Frame(main_frame, style="Main.TFrame")
        split_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # ── Left Column: Config & Paths ──
        left_frame = ttk.Frame(split_frame, style="Main.TFrame")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        # Path Controls
        path_btn_frame = ttk.Frame(left_frame, style="Main.TFrame")
        path_btn_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(path_btn_frame, text="➕ Add File", style="Secondary.TButton", 
                   command=self.add_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(path_btn_frame, text="📁 Add Folder", style="Secondary.TButton", 
                   command=self.add_folder).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(path_btn_frame, text="❌ Remove Selected", style="Secondary.TButton", 
                   command=self.remove_selected).pack(side=tk.RIGHT)

        # Paths Treeview
        self.paths_tree = ttk.Treeview(left_frame, columns=("type", "path"), show="headings", 
                                       style="FIM.Treeview", selectmode="browse")
        self.paths_tree.heading("type", text="Type")
        self.paths_tree.heading("path", text="Target Path")
        self.paths_tree.column("type", width=80, minwidth=60, stretch=tk.NO)
        self.paths_tree.column("path", width=300, minwidth=200)
        self.paths_tree.pack(fill=tk.BOTH, expand=True)

        # ── Right Column: Control & Logs ──
        right_frame = ttk.Frame(split_frame, style="Main.TFrame")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Operations Bar
        ops_frame = ttk.Frame(right_frame, style="Main.TFrame")
        ops_frame.pack(fill=tk.X, pady=(0, 5))

        self.baseline_btn = ttk.Button(ops_frame, text="💾 Generate Baseline", 
                                       style="Primary.TButton", command=self.generate_baseline)
        self.baseline_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.verify_btn = ttk.Button(ops_frame, text="🔍 Verify Integrity", 
                                     style="Primary.TButton", command=self.verify_integrity)
        self.verify_btn.pack(side=tk.LEFT)

        # Output Log Console
        log_label_frame = ttk.Frame(right_frame, style="Main.TFrame")
        log_label_frame.pack(fill=tk.X, pady=(5, 2))
        ttk.Label(log_label_frame, text="Audit Log & Monitoring Reports", style="Standard.TLabel").pack(side=tk.LEFT)

        self.log_text = scrolledtext.ScrolledText(right_frame, bg="#181825", fg=self.fg_color,
                                                 insertbackground=self.fg_color, font=("Consolas", 9),
                                                 relief=tk.FLAT, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    # ────────────────────────── Core Logic ──────────────────────────

    def log(self, message, color_tag=None):
        """Append messages safely to the output log text area."""
        self.log_text.configure(state=tk.NORMAL)
        
        # Configure color formatting tags
        self.log_text.tag_config("green", foreground=self.green)
        self.log_text.tag_config("yellow", foreground=self.yellow)
        self.log_text.tag_config("red", foreground=self.red)
        self.log_text.tag_config("blue", foreground=self.accent_color)

        if color_tag:
            self.log_text.insert(tk.END, message + "\n", color_tag)
        else:
            self.log_text.insert(tk.END, message + "\n")
            
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def calculate_sha256(self, filepath):
        """Calculates SHA-256 hash of a file dynamically in chunks."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256.update(byte_block)
            return sha256.hexdigest()
        except (PermissionError, FileNotFoundError):
            return None

    def get_all_target_files(self):
        """Extracts individual target files from user selected files/folders."""
        target_files = set()
        for item in self.monitored_paths:
            path = item["path"]
            if os.path.isfile(path):
                target_files.add(os.path.abspath(path))
            elif os.path.isdir(path):
                for root_dir, _, files in os.walk(path):
                    for file in files:
                        full_path = os.path.join(root_dir, file)
                        target_files.add(os.path.abspath(full_path))
        return list(target_files)

    # ───────────────────────── State Handling ─────────────────────────

    def save_state(self):
        """Persists targets list and hash baseline to baseline configuration file."""
        data = {
            "monitored_paths": self.monitored_paths,
            "baseline": self.baseline
        }
        try:
            with open(BASELINE_FILE, "w") as f:
                json.dump(data, f, indent=4)
        except IOError as e:
            messagebox.showerror("Error", f"Failed to save baseline data: {e}")

    def load_state(self):
        """Loads baseline database file if it exists."""
        if os.path.exists(BASELINE_FILE):
            try:
                with open(BASELINE_FILE, "r") as f:
                    data = json.load(f)
                    self.monitored_paths = data.get("monitored_paths", [])
                    self.baseline = data.get("baseline", {})
            except Exception:
                pass

    # ─────────────────────── UI Interaction Handlers ───────────────────────

    def refresh_monitored_list(self):
        self.paths_tree.delete(*self.paths_tree.get_children())
        for idx, item in enumerate(self.monitored_paths):
            self.paths_tree.insert("", tk.END, iid=idx, values=(item["type"], item["path"]))

    def add_file(self):
        filepath = filedialog.askopenfilename(title="Select File to Monitor")
        if filepath:
            normalized_path = os.path.abspath(filepath)
            # Check for duplicates
            if not any(item["path"] == normalized_path for item in self.monitored_paths):
                self.monitored_paths.append({"type": "File", "path": normalized_path})
                self.refresh_monitored_list()
                self.save_state()
                self.log(f"[+] Added File watch target: {normalized_path}", "blue")

    def add_folder(self):
        dirpath = filedialog.askdirectory(title="Select Directory to Monitor")
        if dirpath:
            normalized_path = os.path.abspath(dirpath)
            # Check for duplicates
            if not any(item["path"] == normalized_path for item in self.monitored_paths):
                self.monitored_paths.append({"type": "Folder", "path": normalized_path})
                self.refresh_monitored_list()
                self.save_state()
                self.log(f"[+] Added Directory watch target: {normalized_path}", "blue")

    def remove_selected(self):
        selected_item = self.paths_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Select an item from the monitored targets list to remove.")
            return
        
        idx = int(selected_item[0])
        removed = self.monitored_paths.pop(idx)
        self.refresh_monitored_list()
        self.save_state()
        self.log(f"[-] Removed target watch: {removed['path']}")

   

    def generate_baseline(self):
        if not self.monitored_paths:
            messagebox.showwarning("Empty Target", "Please add files or folders to monitor before generating a baseline.")
            return

        self.baseline_btn.configure(state=tk.DISABLED)
        self.verify_btn.configure(state=tk.DISABLED)
        self.log("\n[*] Initiating baseline generation calculations...", "blue")

        threading.Thread(target=self._run_baseline_generation, daemon=True).start()

    def _run_baseline_generation(self):
        target_files = self.get_all_target_files()
        new_baseline = {}
        error_count = 0

        for file_path in target_files:
            file_hash = self.calculate_sha256(file_path)
            if file_hash:
                new_baseline[file_path] = file_hash
            else:
                error_count += 1
                self.log(f"[!] Warning: Could not read / hash: {file_path}", "yellow")

        self.baseline = new_baseline
        self.save_state()
        
        self.log(f"[+] Baseline Generation Complete. Checked: {len(new_baseline)} files.", "green")
        if error_count > 0:
            self.log(f"[!] Blocked/Skipped read errors: {error_count} files.", "yellow")

        self.root.after(0, self._enable_buttons)

    def verify_integrity(self):
        if not self.baseline:
            messagebox.showwarning("No Baseline", "No stored hashes found. Please execute 'Generate Baseline' first.")
            return

        self.baseline_btn.configure(state=tk.DISABLED)
        self.verify_btn.configure(state=tk.DISABLED)
        self.log("\n[*] Starting Integrity Analysis Scan...", "blue")

        threading.Thread(target=self._run_integrity_check, daemon=True).start()

    def _run_integrity_check(self):
        current_target_files = self.get_all_target_files()
        
        # Track baseline states
        missing_files = []
        modified_files = []
        intact_files = []
        new_untracked_files = []

        # 1. Compare current items against baseline database
        for baseline_file, baseline_hash in list(self.baseline.items()):
            if not os.path.exists(baseline_file):
                missing_files.append(baseline_file)
            else:
                current_hash = self.calculate_sha256(baseline_file)
                if current_hash != baseline_hash:
                    modified_files.append(baseline_file)
                else:
                    intact_files.append(baseline_file)

        # 2. Check for newly introduced files in directories that aren't in baseline
        for target_file in current_target_files:
            if target_file not in self.baseline:
                new_untracked_files.append(target_file)

        # ── Output Report to Log Console ──
        if not missing_files and not modified_files and not new_untracked_files:
            self.log("[✓] Verification Succeeded: All monitored files match database hashes.", "green")
        else:
            self.log("[!] WARNING: Integrity mismatches detected!", "red")

        if modified_files:
            self.log(f"\n⚠️  MODIFIED FILES ({len(modified_files)}):", "red")
            for f in modified_files:
                self.log(f"  -> {f}", "red")

        if missing_files:
            self.log(f"\n🚫 MISSING FILES ({len(missing_files)}):", "yellow")
            for f in missing_files:
                self.log(f"  -> {f}", "yellow")

        if new_untracked_files:
            self.log(f"\n➕ NEW UNTRACKED FILES ({len(new_untracked_files)}):", "blue")
            for f in new_untracked_files:
                self.log(f"  -> {f}", "blue")

        self.log(f"\n[*] Scan summary: Total Checked: {len(current_target_files)} | Intact: {len(intact_files)}", "blue")
        self.root.after(0, self._enable_buttons)

    def _enable_buttons(self):
        self.baseline_btn.configure(state=tk.NORMAL)
        self.verify_btn.configure(state=tk.NORMAL)


def main():
    root = tk.Tk()
    app = FileIntegrityMonitorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
