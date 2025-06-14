
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from scanner import core, database
import os
import time

class VirusScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PyScanAV - Virus Scanner")
        self.root.configure(bg="black")
        self.root.attributes('-fullscreen', True)

        self.selected_directory = None
        self.scan_start_time = None

        self.create_widgets()
        self.bind_events()

    def create_widgets(self):
        self.title_label = tk.Label(
            self.root,
            text="PyScanAV - Virus Scanner",
            font=("Courier", 32, "bold"),
            bg="black",
            fg="#00ffaa"
        )
        self.title_label.pack(pady=20)

        # Buttons Frame
        self.button_frame = tk.Frame(self.root, bg="black")
        self.button_frame.pack(pady=10)

        self.select_button = tk.Button(
            self.button_frame,
            text="Select Folder",
            command=self.select_directory,
            bg="black",
            fg="#00ffaa",
            activebackground="#00ffaa",
            activeforeground="black",
            width=15
        )
        self.select_button.pack(side=tk.LEFT, padx=10)

        self.scan_button = tk.Button(
            self.button_frame,
            text="Scan",
            command=self.start_scan,
            bg="black",
            fg="#00ffaa",
            activebackground="#00ffaa",
            activeforeground="black",
            width=15,
            state=tk.DISABLED
        )
        self.scan_button.pack(side=tk.LEFT, padx=10)

        self.clear_button = tk.Button(
            self.button_frame,
            text="Clear Results",
            command=self.clear_results,
            bg="black",
            fg="#00ffaa",
            activebackground="#00ffaa",
            activeforeground="black",
            width=15
        )
        self.clear_button.pack(side=tk.LEFT, padx=10)

        self.exit_button = tk.Button(
            self.button_frame,
            text="Exit",
            command=self.root.destroy,
            bg="black",
            fg="#00ffaa",
            activebackground="#00ffaa",
            activeforeground="black",
            width=15
        )
        self.exit_button.pack(side=tk.LEFT, padx=10)

        self.progress_label = tk.Label(
            self.root,
            text="Progress:",
            bg="black",
            fg="#00ffaa"
        )
        self.progress_label.pack()

        self.progress_bar = ttk.Progressbar(
            self.root,
            orient='horizontal',
            length=500,
            mode='determinate'
        )
        self.progress_bar.pack(pady=5)

        self.result_text = tk.Text(
            self.root,
            height=25,
            width=100,
            bg="black",
            fg="#00ffaa",
            insertbackground="#00ffaa"
        )
        self.result_text.pack(pady=10)

    def bind_events(self):
        self.root.bind("<Escape>", lambda e: self.root.destroy())

    def select_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.selected_directory = directory
            self.result_text.insert(tk.END, f"Selected folder: {directory}\n")
            self.scan_button.config(state=tk.NORMAL)

    def clear_results(self):
        self.result_text.delete(1.0, tk.END)
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Progress:")

    def start_scan(self):
        if not self.selected_directory:
            messagebox.showwarning("Warning", "Please select a folder to scan first.")
            return

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Scanning folder: {self.selected_directory}\n\n")

        signatures = database.load_signatures()

        files_to_scan = []
        for dirpath, _, filenames in os.walk(self.selected_directory):
            for file in filenames:
                files_to_scan.append(os.path.join(dirpath, file))

        total_files = len(files_to_scan)
        if total_files == 0:
            self.result_text.insert(tk.END, "No files found in the selected folder.\n")
            return

        self.progress_bar['maximum'] = total_files
        self.progress_label.config(text="Progress: 0%")

        infected_files = []
        self.scan_start_time = time.time()

        for idx, filepath in enumerate(files_to_scan, 1):
            self.result_text.insert(tk.END, f"Scanning file: {filepath}\n")
            self.root.update_idletasks()

            infected = core.scan_file(filepath, signatures)
            if infected:
                virus_name, source = infected
                infected_files.append((filepath, virus_name, source))
                self.result_text.insert(tk.END, f"*** INFECTED: {filepath} → {virus_name} (Source: {source}) ***\n")
                self.ask_to_delete(filepath)

            self.progress_bar['value'] = idx
            percent = int((idx / total_files) * 100)
            self.progress_label.config(text=f"Progress: {percent}%")

        elapsed = time.time() - self.scan_start_time
        self.result_text.insert(tk.END, f"\nScan completed in {elapsed:.2f} seconds.\n")

        if not infected_files:
            self.result_text.insert(tk.END, "Virus not found.\n")
        else:
            self.result_text.insert(tk.END, "\nScan Summary:\n")
            for path, virus, source in infected_files:
                self.result_text.insert(tk.END, f"[INFECTED] {path} → {virus} (Source: {source})\n")

        self.ask_to_save_report()

    def ask_to_delete(self, filepath):
        response = messagebox.askyesno("Virus Detected",
                                       f"Virus detected in file:\n{filepath}\nDo you want to delete this file?")
        if response:
            try:
                os.remove(filepath)
                self.result_text.insert(tk.END, f"Deleted infected file: {filepath}\n")
            except Exception as e:
                self.result_text.insert(tk.END, f"Failed to delete {filepath}: {str(e)}\n")

    def ask_to_save_report(self):
        response = messagebox.askyesno("Save Report", "Do you want to save the scan report to a file?")
        if response:
            filepath = filedialog.asksaveasfilename(defaultextension=".txt",
                                                    filetypes=[("Text files", "*.txt")])
            if filepath:
                try:
                    with open(filepath, 'w') as f:
                        f.write(self.result_text.get(1.0, tk.END))
                    messagebox.showinfo("Saved", f"Report saved to:\n{filepath}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save report:\n{str(e)}")

if __name__ == '__main__':
    root = tk.Tk()
    app = VirusScannerApp(root)
    root.mainloop()
