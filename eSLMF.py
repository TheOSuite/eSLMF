import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
import threading
import time
import requests
import queue
import json
import os
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse, urljoin
import base64

class SecurityLoggingTesterGUI:
    def __init__(self, master):
        self.master = master
        master.title("Security Logging Tester")

        self.test_parameters = {}
        self.running_tests = {}
        self._stop_threads = False

        self._status_message = tk.StringVar()
        self.status_bar = tk.Label(self.master, textvariable=self._status_message, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_status("Ready")

        self._fl_status = tk.StringVar(value="Ready")
        self._dt_status = tk.StringVar(value="Ready")
        self._dm_status = tk.StringVar(value="Ready")


        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.create_general_tab()
        self.create_failed_logins_tab()
        self.create_directory_traversal_tab()
        self.create_data_modification_tab()

        self.output_label = tk.Label(self.master, text="Output:")
        self.output_label.pack(pady=5)

        self.output_area = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, width=80, height=15)
        self.output_area.pack(padx=10, pady=5, fill="both", expand=True)
        self.output_area.config(state='disabled')

        self.output_area.tag_config('info', foreground='black')
        self.output_area.tag_config('warning', foreground='orange')
        self.output_area.tag_config('error', foreground='red')
        self.output_area.tag_config('success', foreground='green')
        self.output_area.tag_config('header', foreground='blue', font=('TkDefaultFont', 9, 'bold'))


        self.queue = queue.Queue()
        self.master.after(100, self.process_queue)

        self.session = self.create_session()
        self.proxy_list = []

        self.create_control_buttons()

        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)


    def create_session(self):
        """Creates a requests session with retry logic."""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def create_general_tab(self):
        self.general_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.general_tab, text="General")

        self.base_url_label = tk.Label(self.general_tab, text="Base URL:")
        self.base_url_label.grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.base_url_entry = tk.Entry(self.general_tab, width=60)
        self.base_url_entry.grid(row=0, column=1, padx=5, pady=2)

        self.proxy_label = tk.Label(self.general_tab, text="Proxies (one per line, optional):")
        self.proxy_label.grid(row=1, column=0, sticky="nw", padx=5, pady=2)
        self.proxy_text = scrolledtext.ScrolledText(self.general_tab, wrap=tk.WORD, width=60, height=5)
        self.proxy_text.grid(row=1, column=1, padx=5, pady=2)

        self.proxy_file_frame = tk.Frame(self.general_tab)
        self.proxy_file_frame.grid(row=2, column=1, sticky="ew", padx=5, pady=2)

        self.load_proxies_button = tk.Button(self.proxy_file_frame, text="Load Proxies from File", command=self.load_proxies_from_file)
        self.load_proxies_button.pack(side=tk.LEFT, padx=2)

        self.save_proxies_button = tk.Button(self.proxy_file_frame, text="Save Proxies to File", command=self.save_proxies_to_file)
        self.save_proxies_button.pack(side=tk.LEFT, padx=2)


    def create_failed_logins_tab(self):
        self.failed_logins_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.failed_logins_tab, text="Failed Logins")

        self.fl_status_label = tk.Label(self.failed_logins_tab, textvariable=self._fl_status, font=('TkDefaultFont', 9, 'italic'))
        self.fl_status_label.grid(row=0, column=1, sticky="e", padx=5, pady=2)

        tk.Label(self.failed_logins_tab, text="Login URL (full path):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.failed_logins_url_entry = tk.Entry(self.failed_logins_tab, width=60)
        self.failed_logins_url_entry.grid(row=1, column=1, padx=5, pady=2)

        tk.Label(self.failed_logins_tab, text="Username:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.failed_logins_username_entry = tk.Entry(self.failed_logins_tab, width=30)
        self.failed_logins_username_entry.grid(row=2, column=1, padx=5, pady=2)

        tk.Label(self.failed_logins_tab, text="Password Prefix:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.failed_logins_password_prefix_entry = tk.Entry(self.failed_logins_tab, width=30)
        self.failed_logins_password_prefix_entry.grid(row=3, column=1, padx=5, pady=2)

        tk.Label(self.failed_logins_tab, text="Number of Attempts:").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        self.failed_logins_attempts_entry = tk.Entry(self.failed_logins_tab, width=10)
        self.failed_logins_attempts_entry.grid(row=4, column=1, padx=5, pady=2, sticky="w")
        self.failed_logins_attempts_entry.insert(0, "10")

        self.run_failed_logins_button = tk.Button(self.failed_logins_tab, text="Run Failed Logins Test", command=self.run_failed_logins_thread)
        self.run_failed_logins_button.grid(row=5, column=0, columnspan=2, pady=10)

        self.failed_logins_progress = ttk.Progressbar(self.failed_logins_tab, orient="horizontal", length=200, mode="determinate")
        self.failed_logins_progress.grid(row=6, column=0, columnspan=2, pady=5, sticky="ew")
        self.failed_logins_progress.grid_forget()

    def create_directory_traversal_tab(self):
        self.directory_traversal_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.directory_traversal_tab, text="Directory Traversal")

        self.dt_status_label = tk.Label(self.directory_traversal_tab, textvariable=self._dt_status, font=('TkDefaultFont', 9, 'italic'))
        self.dt_status_label.grid(row=0, column=1, sticky="e", padx=5, pady=2)


        tk.Label(self.directory_traversal_tab, text="Target Path (relative to Base URL):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.dt_target_path_entry = tk.Entry(self.directory_traversal_tab, width=60)
        self.dt_target_path_entry.grid(row=1, column=1, padx=5, pady=2)
        self.dt_target_path_entry.insert(0, "/")

        tk.Label(self.directory_traversal_tab, text="Traversal Payloads (one per line):").grid(row=2, column=0, sticky="nw", padx=5, pady=2)
        self.dt_payloads_text = scrolledtext.ScrolledText(self.directory_traversal_tab, wrap=tk.WORD, width=50, height=5)
        self.dt_payloads_text.grid(row=2, column=1, padx=5, pady=2)
        self.dt_payloads_text.insert(tk.END, "../\n../../\n../../../\n%2e%2e%2f\n%2e%2e/\n.././../\n..\;/")

        self.load_dt_payloads_button = tk.Button(self.directory_traversal_tab, text="Load Payloads from File", command=self.load_dt_payloads_from_file)
        self.load_dt_payloads_button.grid(row=3, column=1, sticky="w", padx=5, pady=2)


        tk.Label(self.directory_traversal_tab, text="Custom Headers (Name: Value, one per line):").grid(row=4, column=0, sticky="nw", padx=5, pady=2)
        self.dt_custom_headers_text = scrolledtext.ScrolledText(self.directory_traversal_tab, wrap=tk.WORD, width=50, height=4)
        self.dt_custom_headers_text.grid(row=4, column=1, padx=5, pady=2)


        tk.Label(self.directory_traversal_tab, text="Authentication:").grid(row=5, column=0, sticky="w", padx=5, pady=2)
        self.dt_auth_type = tk.StringVar(value="None")
        self.dt_auth_dropdown = ttk.Combobox(self.directory_traversal_tab, textvariable=self.dt_auth_type,
                                             values=["None", "Basic Auth", "API Key (Header)", "Bearer Token"],
                                             state="readonly")
        self.dt_auth_dropdown.grid(row=5, column=1, sticky="w", padx=5, pady=2)
        self.dt_auth_dropdown.bind("<<ComboboxSelected>>", self.update_dt_auth_fields)

        self.dt_auth_fields_frame = tk.Frame(self.directory_traversal_tab)
        self.dt_auth_fields_frame.grid(row=6, column=0, columnspan=2, sticky="ew", padx=5, pady=2)

        self.update_dt_auth_fields()

        self.run_directory_traversal_button = tk.Button(self.directory_traversal_tab, text="Run Directory Traversal Test", command=self.run_directory_traversal_thread)
        self.run_directory_traversal_button.grid(row=7, column=0, columnspan=2, pady=10)

        self.dt_progress = ttk.Progressbar(self.directory_traversal_tab, orient="horizontal", length=200, mode="determinate")
        self.dt_progress.grid(row=8, column=0, columnspan=2, pady=5, sticky="ew")
        self.dt_progress.grid_forget()

    def update_dt_auth_fields(self, event=None):
        """Updates the visibility and type of authentication input fields for Directory Traversal."""
        for widget in self.dt_auth_fields_frame.winfo_children():
            widget.destroy()

        auth_type = self.dt_auth_type.get()

        if auth_type == "Basic Auth":
            tk.Label(self.dt_auth_fields_frame, text="Username:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
            self.dt_username_entry = tk.Entry(self.dt_auth_fields_frame, width=30)
            self.dt_username_entry.grid(row=0, column=1, sticky="w", padx=5, pady=2)
            tk.Label(self.dt_auth_fields_frame, text="Password:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
            self.dt_password_entry = tk.Entry(self.dt_auth_fields_frame, width=30, show="*")
            self.dt_password_entry.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        elif auth_type == "API Key (Header)":
            tk.Label(self.dt_auth_fields_frame, text="Header Name:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
            self.dt_header_name_entry = tk.Entry(self.dt_auth_fields_frame, width=30)
            self.dt_header_name_entry.grid(row=0, column=1, sticky="w", padx=5, pady=2)
            tk.Label(self.dt_auth_fields_frame, text="Header Value:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
            self.dt_header_value_entry = tk.Entry(self.dt_auth_fields_frame, width=30)
            self.dt_header_value_entry.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        elif auth_type == "Bearer Token":
            tk.Label(self.dt_auth_fields_frame, text="Token:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
            self.dt_token_entry = tk.Entry(self.dt_auth_fields_frame, width=60)
            self.dt_token_entry.grid(row=0, column=1, sticky="w", padx=5, pady=2)

        if auth_type != "None":
             self.dt_auth_fields_frame.grid()
        else:
             self.dt_auth_fields_frame.grid_forget()


    def create_data_modification_tab(self):
        self.data_modification_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.data_modification_tab, text="Data Modification")

        self.dm_status_label = tk.Label(self.data_modification_tab, textvariable=self._dm_status, font=('TkDefaultFont', 9, 'italic'))
        self.dm_status_label.grid(row=0, column=1, sticky="e", padx=5, pady=2)


        tk.Label(self.data_modification_tab, text="API URL (full path):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.dm_api_url_entry = tk.Entry(self.data_modification_tab, width=60)
        self.dm_api_url_entry.grid(row=1, column=1, padx=5, pady=2)

        tk.Label(self.data_modification_tab, text="Data ID:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.dm_data_id_entry = tk.Entry(self.data_modification_tab, width=30)
        self.dm_data_id_entry.grid(row=2, column=1, padx=5, pady=2)

        tk.Label(self.data_modification_tab, text="New Value (used if no body):").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.dm_new_value_entry = tk.Entry(self.data_modification_tab, width=30)
        self.dm_new_value_entry.grid(row=3, column=1, padx=5, pady=2)

        tk.Label(self.data_modification_tab, text="HTTP Method:").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        self.dm_method_type = tk.StringVar(value="PUT")
        self.dm_method_dropdown = ttk.Combobox(self.data_modification_tab, textvariable=self.dm_method_type,
                                             values=["GET", "POST", "PUT", "PATCH", "DELETE"],
                                             state="readonly")
        self.dm_method_dropdown.grid(row=4, column=1, sticky="w", padx=5, pady=2)

        tk.Label(self.data_modification_tab, text="Request Body:").grid(row=5, column=0, sticky="nw", padx=5, pady=2)
        self.dm_request_body_text = scrolledtext.ScrolledText(self.data_modification_tab, wrap=tk.WORD, width=60, height=8)
        self.dm_request_body_text.grid(row=5, column=1, padx=5, pady=2)

        tk.Label(self.data_modification_tab, text="Custom Headers (Name: Value, one per line):").grid(row=6, column=0, sticky="nw", padx=5, pady=2)
        self.dm_custom_headers_text = scrolledtext.ScrolledText(self.data_modification_tab, wrap=tk.WORD, width=60, height=4)
        self.dm_custom_headers_text.grid(row=6, column=1, padx=5, pady=2)

        tk.Label(self.data_modification_tab, text="Authentication:").grid(row=7, column=0, sticky="w", padx=5, pady=2)
        self.dm_auth_type = tk.StringVar(value="None")
        self.dm_auth_dropdown = ttk.Combobox(self.data_modification_tab, textvariable=self.dm_auth_type,
                                             values=["None", "Basic Auth", "API Key (Header)", "Bearer Token"],
                                             state="readonly")
        self.dm_auth_dropdown.grid(row=7, column=1, sticky="w", padx=5, pady=2)
        self.dm_auth_dropdown.bind("<<ComboboxSelected>>", self.update_dm_auth_fields)

        self.dm_auth_fields_frame = tk.Frame(self.data_modification_tab)
        self.dm_auth_fields_frame.grid(row=8, column=0, columnspan=2, sticky="ew", padx=5, pady=2)

        self.update_dm_auth_fields()

        tk.Label(self.data_modification_tab, text="Verification URL (Optional):").grid(row=9, column=0, sticky="w", padx=5, pady=2)
        self.dm_verify_url_entry = tk.Entry(self.data_modification_tab, width=60)
        self.dm_verify_url_entry.grid(row=9, column=1, padx=5, pady=2)


        self.run_data_modification_button = tk.Button(self.data_modification_tab, text="Run Data Modification Test", command=self.run_data_modification_thread)
        self.run_data_modification_button.grid(row=10, column=0, columnspan=2, pady=10)

        self.dm_progress = ttk.Progressbar(self.data_modification_tab, orient="horizontal", length=200, mode="determinate")
        self.dm_progress.grid(row=11, column=0, columnspan=2, pady=5, sticky="ew")
        self.dm_progress.grid_forget()


    def update_dm_auth_fields(self, event=None):
        """Updates the visibility and type of authentication input fields for Data Modification."""
        for widget in self.dm_auth_fields_frame.winfo_children():
            widget.destroy()

        auth_type = self.dm_auth_type.get()

        if auth_type == "Basic Auth":
            tk.Label(self.dm_auth_fields_frame, text="Username:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
            self.dm_username_entry = tk.Entry(self.dm_auth_fields_frame, width=30)
            self.dm_username_entry.grid(row=0, column=1, sticky="w", padx=5, pady=2)
            tk.Label(self.dm_auth_fields_frame, text="Password:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
            self.dm_password_entry = tk.Entry(self.dm_auth_fields_frame, width=30, show="*")
            self.dm_password_entry.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        elif auth_type == "API Key (Header)":
            tk.Label(self.dm_auth_fields_frame, text="Header Name:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
            self.dm_header_name_entry = tk.Entry(self.dm_auth_fields_frame, width=30)
            self.dm_header_name_entry.grid(row=0, column=1, sticky="w", padx=5, pady=2)
            tk.Label(self.dm_auth_fields_frame, text="Header Value:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
            self.dm_header_value_entry = tk.Entry(self.dm_auth_fields_frame, width=30)
            self.dm_header_value_entry.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        elif auth_type == "Bearer Token":
            tk.Label(self.dm_auth_fields_frame, text="Token:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
            self.dm_token_entry = tk.Entry(self.dm_auth_fields_frame, width=60)
            self.dm_token_entry.grid(row=0, column=1, sticky="w", padx=5, pady=2)

        if auth_type != "None":
             self.dm_auth_fields_frame.grid()
        else:
             self.dm_auth_fields_frame.grid_forget()


    def create_control_buttons(self):
        """Creates buttons for saving/loading settings and canceling tests."""
        control_frame = tk.Frame(self.master)
        control_frame.pack(pady=10)

        save_button = tk.Button(control_frame, text="Save Settings (No Credentials)", command=lambda: self.save_settings(include_credentials=False))
        save_button.pack(side=tk.LEFT, padx=5)

        load_button = tk.Button(control_frame, text="Load Settings (No Credentials)", command=lambda: self.load_settings(include_credentials=False))
        load_button.pack(side=tk.LEFT, padx=5)

        ttk.Separator(control_frame, orient='vertical').pack(side=tk.LEFT, padx=10, fill='y')

        save_creds_button = tk.Button(control_frame, text="Save Settings (Include Credentials)", command=lambda: self.save_settings(include_credentials=True), fg="red")
        save_creds_button.pack(side=tk.LEFT, padx=5)

        load_creds_button = tk.Button(control_frame, text="Load Settings (Include Credentials)", command=lambda: self.load_settings(include_credentials=True), fg="red")
        load_creds_button.pack(side=tk.LEFT, padx=5)

        ttk.Separator(control_frame, orient='vertical').pack(side=tk.LEFT, padx=10, fill='y')

        cancel_button = tk.Button(control_frame, text="Cancel All Tests", command=self.cancel_all_tests)
        cancel_button.pack(side=tk.LEFT, padx=5)

    def update_output(self, message, severity='info'):
        """Safely updates the output text area from any thread, with optional highlighting."""
        self.output_area.config(state='normal')
        self.output_area.insert(tk.END, message + "\n", severity)
        self.output_area.see(tk.END)
        self.output_area.config(state='disabled')

    def update_status(self, message):
        """Safely updates the main status bar from any thread."""
        self._status_message.set(message)

    def update_tab_status(self, tab_name, message, color=None):
        """Safely updates the status label for a specific tab."""
        if tab_name == "failed_logins":
            self._fl_status.set(message)
            if color:
                self.fl_status_label.config(fg=color)
            else:
                 self.fl_status_label.config(fg="black")
        elif tab_name == "directory_traversal":
            self._dt_status.set(message)
            if color:
                self.dt_status_label.config(fg=color)
            else:
                 self.dt_status_label.config(fg="black")
        elif tab_name == "data_modification":
            self._dm_status.set(message)
            if color:
                self.dm_status_label.config(fg=color)
            else:
                 self.dm_status_label.config(fg="black")


    def process_queue(self):
        """Processes messages from the queue and updates the GUI."""
        try:
            while True:
                message, severity = self.queue.get_nowait()
                self.update_output(message, severity)
        except queue.Empty:
            pass
        finally:
            self.master.after(100, self.process_queue)

    def queue_message(self, message, severity='info'):
        """Adds a message with severity to the queue."""
        self.queue.put((message, severity))


    def get_proxies(self):
        """Retrieves and formats the list of proxies from the text area."""
        proxy_text = self.proxy_text.get("1.0", tk.END).strip()
        self.proxy_list = [line.strip() for line in proxy_text.splitlines() if line.strip()]
        return self.proxy_list

    def get_random_proxy(self):
        """Returns a randomly selected proxy or None if no proxies are configured."""
        proxies = self.get_proxies()
        if proxies:
            try:
                proxy_url = random.choice(proxies)
                return {"http": proxy_url, "https": proxy_url}
            except IndexError:
                 return None
            except Exception as e:
                 self.queue_message(f"Error selecting proxy: {e}", 'error')
                 self.update_status(f"Error selecting proxy: {e}")
                 return None
        return None

    def load_proxies_from_file(self):
        """Loads proxy list from a text file."""
        file_path = filedialog.askopenfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Load Proxies from File"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    proxies = f.read().strip()
                self.proxy_text.delete("1.0", tk.END)
                self.proxy_text.insert(tk.END, proxies)
                self.queue_message(f"Proxies loaded from {os.path.basename(file_path)}", 'info')
                self.update_status(f"Proxies loaded from {os.path.basename(file_path)}")
            except FileNotFoundError:
                 messagebox.showerror("Load Error", f"Proxy file not found: {file_path}")
                 self.queue_message(f"Error loading proxies: File not found: {file_path}", 'error')
                 self.update_status("Error loading proxies: File not found")
            except Exception as e:
                messagebox.showerror("Load Error", f"Failed to load proxies: {e}")
                self.queue_message(f"Error loading proxies: {e}", 'error')
                self.update_status("Error loading proxies")

    def save_proxies_to_file(self):
        """Saves current proxy list to a text file."""
        proxies = self.proxy_text.get("1.0", tk.END).strip()
        if not proxies:
            messagebox.showwarning("No Proxies", "There are no proxies to save.")
            self.update_status("No proxies to save")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Proxies to File"
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(proxies)
                self.queue_message(f"Proxies saved to {os.path.basename(file_path)}", 'info')
                self.update_status(f"Proxies saved to {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save proxies: {e}")
                self.queue_message(f"Error saving proxies: {e}", 'error')
                self.update_status("Error saving proxies")

    def load_dt_payloads_from_file(self):
        """Loads directory traversal payloads from a text file."""
        file_path = filedialog.askopenfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Load Directory Traversal Payloads from File"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    payloads = f.read().strip()
                self.dt_payloads_text.delete("1.0", tk.END)
                self.dt_payloads_text.insert(tk.END, payloads)
                self.queue_message(f"Directory traversal payloads loaded from {os.path.basename(file_path)}", 'info')
                self.update_status(f"DT Payloads loaded from {os.path.basename(file_path)}")
            except FileNotFoundError:
                 messagebox.showerror("Load Error", f"Payload file not found: {file_path}")
                 self.queue_message(f"Error loading payloads: File not found: {file_path}", 'error')
                 self.update_status("Error loading DT payloads: File not found")
            except Exception as e:
                messagebox.showerror("Load Error", f"Failed to load payloads: {e}")
                self.queue_message(f"Error loading payloads: {e}", 'error')
                self.update_status("Error loading DT payloads")


    def validate_url(self, url):
        """Basic URL validation, allows URLs without scheme if netloc exists."""
        if not url:
            return False
        try:
            result = urlparse(url)
            # Consider valid if it has a scheme OR if it has a netloc (like domain.com)
            return (result.scheme in ['http', 'https'] and result.netloc) or (not result.scheme and result.netloc)
        except Exception as e:
            print(f"URL validation error for '{url}': {e}")
            return False

    def normalize_url(self, url):
        """Adds http:// scheme if missing."""
        if not url:
            return ""
        if not urlparse(url).scheme:
            return "http://" + url
        return url

    def safe_entry_get(self, entry_widget):
        """Safely gets text from an Entry widget, returning '' if the widget doesn't exist."""
        try:
            return entry_widget.get().strip()
        except AttributeError:
            return ""

    def safe_entry_insert(self, entry_widget, value):
        """Safely inserts text into an Entry widget, handling potential AttributeError."""
        try:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, value)
        except AttributeError:
             pass

    def safe_scrolledtext_get(self, text_widget):
        """Safely gets text from a ScrolledText widget, returning '' if the widget doesn't exist."""
        try:
            return text_widget.get("1.0", tk.END).strip()
        except AttributeError:
            return ""

    def safe_scrolledtext_insert(self, text_widget, value):
        """Safely inserts text into a ScrolledText widget, handling potential AttributeError."""
        try:
            text_widget.delete("1.0", tk.END)
            text_widget.insert(tk.END, value)
        except AttributeError:
            pass

    def parse_headers_string(self, headers_string):
        """Parses a string of headers (one per line, 'Name: Value') into a dictionary."""
        headers = {}
        for line in headers_string.splitlines():
            line = line.strip()
            if line and ':' in line:
                try:
                    name, value = line.split(':', 1)
                    headers[name.strip()] = value.strip()
                except Exception as e:
                    self.queue_message(f"Warning: Could not parse header line '{line}': {e}", 'warning')

        return headers


    def get_auth_headers(self, auth_params):
        """Constructs headers and auth tuple based on the authentication parameters."""
        headers = {}
        auth_arg = None
        auth_type = auth_params.get("auth_type", "None")

        if auth_type == "Basic Auth":
            username = auth_params.get("username")
            password = auth_params.get("password")
            if username and password:
                auth_arg = (username, password)
        elif auth_type == "API Key (Header)":
            header_name = auth_params.get("header_name")
            header_value = auth_params.get("header_value")
            if header_name and header_value:
                headers[header_name] = header_value
        elif auth_type == "Bearer Token":
            token = auth_params.get("token")
            if token:
                headers['Authorization'] = f'Bearer {token}'

        return auth_arg, headers


    def run_failed_logins_thread(self):
        login_url = self.failed_logins_url_entry.get().strip()
        username = self.failed_logins_username_entry.get().strip()
        password_prefix = self.failed_logins_password_prefix_entry.get().strip()

        normalized_login_url = self.normalize_url(login_url)

        if not self.validate_url(normalized_login_url):
             messagebox.showerror("Invalid Input", "Please enter a valid Login URL (e.g., example.com or https://example.com).")
             self.update_status("Invalid Login URL")
             self.update_tab_status("failed_logins", "Validation Error", "red")
             return
        if not username or not password_prefix:
             messagebox.showwarning("Missing Input", "Please fill in Username and Password Prefix for failed logins.")
             self.update_status("Missing Failed Login parameters")
             self.update_tab_status("failed_logins", "Missing Input", "red")
             return

        try:
            num_attempts = int(self.failed_logins_attempts_entry.get())
            if num_attempts <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Input", "Number of attempts must be a positive integer.")
            self.update_status("Invalid Number of Attempts")
            self.update_tab_status("failed_logins", "Validation Error", "red")
            return

        self.run_failed_logins_button.config(state='disabled')
        self.failed_logins_progress.config(mode="determinate", maximum=num_attempts, value=0)
        self.failed_logins_progress.grid(row=6, column=0, columnspan=2, pady=5, sticky="ew")

        self.queue_message("--- Starting Failed Logins Test ---", 'header')
        self.update_status("Running Failed Logins Test...")
        self.update_tab_status("failed_logins", "Running...", "blue")


        thread_name = "failed_logins"
        thread = threading.Thread(target=self.perform_failed_logins_test, args=(normalized_login_url, username, password_prefix, num_attempts, thread_name))
        self.running_tests[thread_name] = thread
        thread.start()

    def perform_failed_logins_test(self, url, username, password_prefix, num_attempts, test_name):
        try:
            for i in range(num_attempts):
                if self._stop_threads:
                    self.queue_message(f"Test '{test_name}' cancelled.", 'warning')
                    self.update_tab_status(test_name, "Cancelled", "orange")
                    break

                incorrect_password = f"{password_prefix}{i+1}"
                message = f"Attempt {i+1}/{num_attempts}: Trying password '{incorrect_password}'..."
                self.queue_message(message, 'info')
                self.update_status(f"Failed Logins: Attempt {i+1}/{num_attempts}")


                try:
                    proxies = self.get_random_proxy()
                    response = self.session.post(url, data={'username': username, 'password': incorrect_password}, timeout=10, proxies=proxies)
                    status_code = response.status_code
                    self.queue_message(f"  Status Code: {status_code}", 'info')
                    if response.status_code in [401, 403]:
                         self.queue_message("  Likely authentication/authorization failure (expected).", 'info')

                except requests.exceptions.Timeout:
                     self.queue_message("  Request timed out.", 'error')
                     self.update_status("Failed Logins: Request timed out")
                     self.update_tab_status(test_name, "Error", "red")
                     break
                except requests.exceptions.ConnectionError:
                     self.queue_message("  Connection error occurred.", 'error')
                     self.update_status("Failed Logins: Connection Error")
                     self.update_tab_status(test_name, "Error", "red")
                     break
                except requests.exceptions.RequestException as e:
                     self.queue_message(f"  Request error: {e}", 'error')
                     self.update_status(f"Failed Logins: Request Error ({type(e).__name__})")
                     self.update_tab_status(test_name, "Error", "red")
                     break
                except Exception as e:
                     self.queue_message(f"  An unexpected error occurred: {e}", 'error')
                     self.update_status(f"Failed Logins: Unexpected Error ({type(e).__name__})")
                     self.update_tab_status(test_name, "Error", "red")
                     break


                self.master.after(0, self.failed_logins_progress.config, {'value': i + 1})
                time.sleep(0.2)

            if not self._stop_threads and self._fl_status.get() not in ["Cancelled", "Error"]:
                self.queue_message("\nFailed login attempts completed.", 'success')
                self.queue_message("=> Manually check your security logs for entries related to failed logins from your IP.", 'info')
                self.update_status("Failed Logins Test Completed")
                self.update_tab_status(test_name, "Completed", "green")


        finally:
            self.master.after(0, self.run_failed_logins_button.config, {'state': 'normal'})
            self.master.after(0, self.failed_logins_progress.grid_forget)
            if test_name in self.running_tests:
                del self.running_tests[test_name]
            if not self.running_tests:
                 self.update_status("Ready")

            if self._fl_status.get() not in ["Cancelled", "Error", "Validation Error", "Missing Input"]:
                 self.update_tab_status(test_name, "Ready", "black")

            self._stop_threads = False


    def run_directory_traversal_thread(self):
        base_url = self.base_url_entry.get().strip()
        target_path = self.dt_target_path_entry.get().strip()
        payloads = [p.strip() for p in self.dt_payloads_text.get("1.0", tk.END).strip().split('\n') if p.strip()]
        custom_headers_string = self.safe_scrolledtext_get(self.dt_custom_headers_text)
        auth_type = self.dt_auth_type.get()

        normalized_base_url = self.normalize_url(base_url)

        if not self.validate_url(normalized_base_url):
             messagebox.showerror("Invalid Input", "Please enter a valid Base URL (e.g., example.com or https://example.com).")
             self.update_status("Invalid Base URL")
             self.update_tab_status("directory_traversal", "Validation Error", "red")
             return
        if not target_path or not payloads:
            messagebox.showwarning("Missing Input", "Please fill in Target Path and Traversal Payloads.")
            self.update_status("Missing Directory Traversal parameters")
            self.update_tab_status("directory_traversal", "Missing Input", "red")
            return

        auth_params = {"auth_type": auth_type}
        if auth_type == "Basic Auth":
            auth_params["username"] = self.safe_entry_get(getattr(self, 'dt_username_entry', None))
            auth_params["password"] = self.safe_entry_get(getattr(self, 'dt_password_entry', None))
            if not auth_params["username"] or not auth_params["password"]:
                 messagebox.showwarning("Missing Input", "Please provide Username and Password for Basic Auth.")
                 self.update_status("Missing Basic Auth credentials")
                 self.update_tab_status("directory_traversal", "Missing Auth Input", "red")
                 return
        elif auth_type == "API Key (Header)":
            auth_params["header_name"] = self.safe_entry_get(getattr(self, 'dt_header_name_entry', None))
            auth_params["header_value"] = self.safe_entry_get(getattr(self, 'dt_header_value_entry', None))
            if not auth_params["header_name"] or not auth_params["header_value"]:
                 messagebox.showwarning("Missing Input", "Please provide Header Name and Value for API Key Auth.")
                 self.update_status("Missing API Key credentials")
                 self.update_tab_status("directory_traversal", "Missing Auth Input", "red")
                 return
        elif auth_type == "Bearer Token":
             auth_params["token"] = self.safe_entry_get(getattr(self, 'dt_token_entry', None))
             if not auth_params["token"]:
                 messagebox.showwarning("Missing Input", "Please provide the Token for Bearer Token Auth.")
                 self.update_status("Missing Bearer Token")
                 self.update_tab_status("directory_traversal", "Missing Auth Input", "red")
                 return

        try:
            custom_headers = self.parse_headers_string(custom_headers_string)
        except Exception as e:
             messagebox.showerror("Header Parse Error", f"Failed to parse custom headers: {e}")
             self.update_status("Error parsing custom headers")
             self.update_tab_status("directory_traversal", "Header Parse Error", "red")
             return


        self.run_directory_traversal_button.config(state='disabled')
        self.dt_progress.config(mode="determinate", maximum=len(payloads), value=0)
        self.dt_progress.grid(row=8, column=0, columnspan=2, pady=5, sticky="ew")


        self.queue_message("--- Starting Directory Traversal Test ---", 'header')
        self.update_status("Running Directory Traversal Test...")
        self.update_tab_status("directory_traversal", "Running...", "blue")


        thread_name = "directory_traversal"
        thread = threading.Thread(target=self.perform_directory_traversal_test, args=(normalized_base_url, target_path, payloads, auth_params, custom_headers, thread_name))
        self.running_tests[thread_name] = thread
        thread.start()

    def perform_directory_traversal_test(self, base_url, target_path, payloads, auth_params, custom_headers, test_name):
        auth_arg, auth_headers = self.get_auth_headers(auth_params)

        merged_headers = auth_headers.copy()
        merged_headers.update(custom_headers)

        parsed_base_url = urlparse(base_url)


        try:
            for i in range(len(payloads)):
                if self._stop_threads:
                    self.queue_message(f"Test '{test_name}' cancelled.", 'warning')
                    self.update_tab_status(test_name, "Cancelled", "orange")
                    break

                payload = payloads[i]

                # Construct the full path
                # Ensure base_url path ends with a slash if it's not empty, unless it's just "/"
                base_path = parsed_base_url.path if parsed_base_url.path != "/" else ""
                if base_path and not base_path.endswith('/'):
                    base_path += '/'

                # Ensure target_path has a leading slash if not empty
                normalized_target_path = target_path
                if normalized_target_path and not normalized_target_path.startswith('/'):
                     normalized_target_path = '/' + normalized_target_path

                # Combine paths, handling leading/trailing slashes carefully
                combined_path = urljoin(base_path, normalized_target_path.lstrip('/')) # Join base path and target path first
                combined_path = urljoin(combined_path + '/', payload.lstrip('/')) # Then join with payload


                # Construct the full URL using the parsed components and the new combined path
                test_url = parsed_base_url._replace(path=combined_path).geturl()


                message = f"Attempt {i+1}/{len(payloads)}: Trying URL '{test_url}'..."
                self.queue_message(message, 'info')
                self.update_status(f"Directory Traversal: Attempt {i+1}/{len(payloads)}")


                try:
                    proxies = self.get_random_proxy()
                    response = self.session.get(test_url, timeout=10, proxies=proxies, auth=auth_arg, headers=merged_headers)
                    status_code = response.status_code
                    self.queue_message(f"  Status Code: {status_code}", 'info')
                    if status_code == 200:
                         self.queue_message(f"  Potential Success (Status 200)! Check response content.", 'success')
                         if "root:" in response.text or "admin:" in response.text or "windows" in response.text.lower():
                             self.queue_message("  Possible sensitive file content detected in response.", 'success')
                    elif status_code in [401, 403]:
                         self.queue_message(f"  Access Denied (Status {status_code}). Expected behavior if authorized.", 'info')
                    else:
                         self.queue_message(f"  Unexpected Status Code: {status_code}", 'warning')

                except requests.exceptions.Timeout:
                     self.queue_message("  Request timed out.", 'error')
                     self.update_status("Directory Traversal: Request timed out")
                     self.update_tab_status(test_name, "Error", "red")
                     break
                except requests.exceptions.ConnectionError:
                     self.queue_message("  Connection error occurred.", 'error')
                     self.update_status("Directory Traversal: Connection Error")
                     self.update_tab_status(test_name, "Error", "red")
                     break
                except requests.exceptions.RequestException as e:
                    self.queue_message(f"  Request error: {e}", 'error')
                    self.update_status(f"Directory Traversal: Request Error ({type(e).__name__})")
                    self.update_tab_status(test_name, "Error", "red")
                    break
                except Exception as e:
                    self.queue_message(f"  An unexpected error occurred: {e}", 'error')
                    self.update_status(f"Directory Traversal: Unexpected Error ({type(e).__name__})")
                    self.update_tab_status(test_name, "Error", "red")
                    break


                self.master.after(0, self.dt_progress.config, {'value': i + 1})
                time.sleep(0.5)

            if not self._stop_threads and self._dt_status.get() not in ["Cancelled", "Error"]:
                self.queue_message("\nDirectory Traversal test completed.", 'success')
                self.queue_message("=> Review the output for any successful requests (e.g., status code 200) and analyze the content.", 'info')
                self.update_status("Directory Traversal Test Completed")
                self.update_tab_status(test_name, "Completed", "green")


        finally:
            self.master.after(0, self.run_directory_traversal_button.config, {'state': 'normal'})
            self.master.after(0, self.dt_progress.grid_forget)
            if test_name in self.running_tests:
                del self.running_tests[test_name]
            if not self.running_tests:
                 self.update_status("Ready")

            if self._dt_status.get() not in ["Cancelled", "Error", "Validation Error", "Missing Input", "Missing Auth Input", "Header Parse Error"]:
                 self.update_tab_status(test_name, "Ready", "black")

            self._stop_threads = False


    def run_data_modification_thread(self):
        api_url = self.dm_api_url_entry.get().strip()
        data_item_id = self.dm_data_id_entry.get().strip()
        new_data_value = self.dm_new_value_entry.get().strip()
        http_method = self.dm_method_type.get()
        request_body_string = self.safe_scrolledtext_get(self.dm_request_body_text)
        custom_headers_string = self.safe_scrolledtext_get(self.dm_custom_headers_text)
        auth_type = self.dm_auth_type.get()
        verify_url = self.safe_entry_get(self.dm_verify_url_entry)

        normalized_api_url = self.normalize_url(api_url)
        normalized_verify_url = self.normalize_url(verify_url) if verify_url else ""


        if not self.validate_url(normalized_api_url):
             messagebox.showerror("Invalid Input", "Please enter a valid API URL (e.g., example.com/api/data).")
             self.update_status("Invalid API URL")
             self.update_tab_status("data_modification", "Validation Error", "red")
             return

        auth_params = {"auth_type": auth_type}
        if auth_type == "Basic Auth":
            auth_params["username"] = self.safe_entry_get(getattr(self, 'dm_username_entry', None))
            auth_params["password"] = self.safe_entry_get(getattr(self, 'dm_password_entry', None))
            if not auth_params["username"] or not auth_params["password"]:
                 messagebox.showwarning("Missing Input", "Please provide Username and Password for Basic Auth.")
                 self.update_status("Missing Basic Auth credentials")
                 self.update_tab_status("data_modification", "Missing Auth Input", "red")
                 return
        elif auth_type == "API Key (Header)":
            auth_params["header_name"] = self.safe_entry_get(getattr(self, 'dm_header_name_entry', None))
            auth_params["header_value"] = self.safe_entry_get(getattr(self, 'dm_header_value_entry', None))
            if not auth_params["header_name"] or not auth_params["header_value"]:
                 messagebox.showwarning("Missing Input", "Please provide Header Name and Value for API Key Auth.")
                 self.update_status("Missing API Key credentials")
                 self.update_tab_status("data_modification", "Missing Auth Input", "red")
                 return
        elif auth_type == "Bearer Token":
             auth_params["token"] = self.safe_entry_get(getattr(self, 'dm_token_entry', None))
             if not auth_params["token"]:
                 messagebox.showwarning("Missing Input", "Please provide the Token for Bearer Token Auth.")
                 self.update_status("Missing Bearer Token")
                 self.update_tab_status("data_modification", "Missing Auth Input", "red")
                 return

        if normalized_verify_url and not self.validate_url(normalized_verify_url):
             messagebox.showwarning("Invalid Input", "Verification URL is not a valid URL.")
             self.update_status("Invalid Verification URL")
             self.update_tab_status("data_modification", "Validation Error", "red")
             return

        try:
            custom_headers = self.parse_headers_string(custom_headers_string)
        except Exception as e:
             messagebox.showerror("Header Parse Error", f"Failed to parse custom headers: {e}")
             self.update_status("Error parsing custom headers")
             self.update_tab_status("data_modification", "Header Parse Error", "red")
             return


        self.run_data_modification_button.config(state='disabled')
        self.dm_progress.config(mode="indeterminate")
        self.dm_progress.grid(row=11, column=0, columnspan=2, pady=5, sticky="ew")
        self.dm_progress.start()

        self.queue_message("--- Starting Data Modification Test ---", 'header')
        self.update_status("Running Data Modification Test...")
        self.update_tab_status("data_modification", "Running...", "blue")


        thread_name = "data_modification"
        thread = threading.Thread(target=self.perform_data_modification_test, args=(normalized_api_url, data_item_id, new_data_value, http_method, request_body_string, normalized_verify_url, auth_params, custom_headers, thread_name))
        self.running_tests[thread_name] = thread
        thread.start()

    def perform_data_modification_test(self, api_url, data_item_id, new_value, http_method, request_body_string, verify_url, auth_params, custom_headers, test_name):
        auth_arg, auth_headers = self.get_auth_headers(auth_params)

        merged_headers = auth_headers.copy()
        merged_headers.update(custom_headers)

        request_data = None
        request_json = None
        body_content_str = request_body_string.strip()

        if body_content_str:
            try:
                request_json = json.loads(body_content_str)
            except json.JSONDecodeError:
                 request_data = body_content_str

        if not body_content_str and http_method in ["POST", "PUT", "PATCH", "DELETE"]:
             self.queue_message("No explicit request body provided. Using Data ID and New Value fields to construct a simple JSON body...", 'info')
             request_json = {'id': data_item_id, 'value': new_value}


        try:
            if self._stop_threads:
                self.queue_message(f"Test '{test_name}' cancelled.", 'warning')
                self.update_tab_status(test_name, "Cancelled", "orange")
                return

            self.queue_message(f"Attempting to send {http_method} request to '{api_url}'...", 'info')
            status_message = f"Data Modification: Sending {http_method} request..."
            if request_json is not None:
                 status_message += " (JSON body)"
            elif request_data is not None:
                 status_message += " (raw body)"
            self.update_status(status_message)


            try:
                proxies = self.get_random_proxy()
                response = self.session.request(
                    http_method,
                    api_url,
                    json=request_json,
                    data=request_data,
                    timeout=10,
                    proxies=proxies,
                    auth=auth_arg,
                    headers=merged_headers
                )
                status_code = response.status_code
                self.queue_message(f"  Status Code: {status_code}", 'info')
                self.queue_message(f"  Response Body Snippet:\n{response.text[:300]}...\n", 'info')

                if 200 <= status_code < 300:
                     self.queue_message("  Modification request likely successful (Status 2xx).", 'success')
                elif status_code in [401, 403]:
                     self.queue_message(f"  Access Denied (Status {status_code}). Check credentials/permissions.", 'warning')
                else:
                     self.queue_message(f"  Modification request failed or unexpected status: {status_code}.", 'warning')


            except requests.exceptions.Timeout:
                 self.queue_message("  Request timed out.", 'error')
                 self.update_status("Data Modification: Request timed out")
                 self.update_tab_status(test_name, "Error", "red")
                 return
            except requests.exceptions.ConnectionError:
                 self.queue_message("  Connection error occurred.", 'error')
                 self.update_status("Data Modification: Connection Error")
                 self.update_tab_status(test_name, "Error", "red")
                 return
            except requests.exceptions.RequestException as e:
                 self.queue_message(f"  Request error: {e}", 'error')
                 self.update_status(f"Data Modification: Request Error ({type(e).__name__})")
                 self.update_tab_status(test_name, "Error", "red")
                 return
            except Exception as e:
                 self.queue_message(f"  An unexpected error occurred during modification request: {e}", 'error')
                 self.update_status(f"Data Modification: Unexpected Error ({type(e).__name__})")
                 self.update_tab_status(test_name, "Error", "red")
                 return


            # --- Verification Step (Optional) ---
            if verify_url and not self._stop_threads:
                self.queue_message("\nAttempting to verify data modification...", 'info')
                self.update_status("Data Modification: Verifying modification...")

                try:
                    verify_url_final = verify_url # ADAPT THIS LINE IF YOUR VERIFY URL NEEDS THE ID APPENDED

                    proxies = self.get_random_proxy()
                    verify_response = self.session.get(verify_url_final, timeout=10, proxies=proxies, auth=auth_arg, headers=merged_headers)
                    verify_status_code = verify_response.status_code
                    self.queue_message(f"  Verification Request Status Code: {verify_status_code}", 'info')

                    if verify_status_code == 200:
                        self.queue_message("  Verification request successful (Status 200).", 'info')
                        try:
                            verify_content = verify_response.text
                            if str(data_item_id) in verify_content and str(new_value) in verify_content:
                                self.queue_message("  New value FOUND in verification response content.", 'success')
                            else:
                                self.queue_message("  New value NOT FOUND in verification response content.", 'warning')

                            self.queue_message(f"  Verification response snippet:\n{verify_content[:300]}...\n", 'info')

                        except Exception as e:
                            self.queue_message(f"  Error processing verification response content: {e}", 'error')


                    else:
                         self.queue_message(f"  Verification request failed or unexpected status: {verify_status_code}.", 'warning')


                except requests.exceptions.Timeout:
                     self.queue_message("  Verification request timed out.", 'error')
                     self.update_status("Data Modification: Verification timed out")
                except requests.exceptions.ConnectionError:
                     self.queue_message("  Verification connection error occurred.", 'error')
                     self.update_status("Data Modification: Verification Connection Error")
                except requests.exceptions.RequestException as e:
                     self.queue_message(f"  Verification request error: {e}", 'error')
                     self.update_status(f"Data Modification: Verification Error ({type(e).__name__})")
                except Exception as e:
                     self.queue_message(f"  An unexpected error occurred during verification request: {e}", 'error')
                     self.update_status(f"Data Modification: Verification Unexpected Error ({type(e).__name__})")


            if not self._stop_threads and self._dm_status.get() not in ["Cancelled", "Error"]:
                self.queue_message("\nData Modification test completed.", 'success')
                self.queue_message("=> Manually check application/database logs to see if the modification was logged.", 'info')
                self.update_status("Data Modification Test Completed")
                self.update_tab_status(test_name, "Completed", "green")


        finally:
            self.master.after(0, self.run_data_modification_button.config, {'state': 'normal'})
            self.master.after(0, self.dm_progress.stop)
            self.master.after(0, self.dm_progress.grid_forget)
            if test_name in self.running_tests:
                del self.running_tests[test_name]
            if not self.running_tests:
                 self.update_status("Ready")

            if self._dm_status.get() not in ["Cancelled", "Error", "Validation Error", "Missing Input", "Missing Auth Input", "Header Parse Error"]:
                self.update_tab_status(test_name, "Ready", "black")

            self._stop_threads = False


    def save_settings(self, include_credentials=False):
        """Saves current settings to a JSON file."""
        settings = {
            "general": {
                "base_url": self.base_url_entry.get().strip(),
                "proxies": self.proxy_text.get("1.0", tk.END).strip()
            },
            "failed_logins": {
                "login_url": self.failed_logins_url_entry.get().strip(),
                "username": self.failed_logins_username_entry.get().strip() if include_credentials else "",
                "password_prefix": self.failed_logins_password_prefix_entry.get().strip() if include_credentials else "",
                "num_attempts": self.failed_logins_attempts_entry.get().strip()
            },
            "directory_traversal": {
                "target_path": self.dt_target_path_entry.get().strip(),
                "payloads": self.dt_payloads_text.get("1.0", tk.END).strip(),
                "custom_headers": self.safe_scrolledtext_get(self.dt_custom_headers_text),
                "auth_type": self.dt_auth_type.get(),
                "auth_params": {
                    "auth_type": self.dt_auth_type.get(),
                    "username": self.safe_entry_get(getattr(self, 'dt_username_entry', None)) if include_credentials and self.dt_auth_type.get() == "Basic Auth" else "",
                    "password": self.safe_entry_get(getattr(self, 'dt_password_entry', None)) if include_credentials and self.dt_auth_type.get() == "Basic Auth" else "",
                    "header_name": self.safe_entry_get(getattr(self, 'dt_header_name_entry', None)) if include_credentials and self.dt_auth_type.get() == "API Key (Header)" else "",
                    "header_value": self.safe_entry_get(getattr(self, 'dt_header_value_entry', None)) if include_credentials and self.dt_auth_type.get() == "API Key (Header)" else "",
                    "token": self.safe_entry_get(getattr(self, 'dt_token_entry', None)) if include_credentials and self.dt_auth_type.get() == "Bearer Token" else ""
                } if include_credentials else {"auth_type": self.dt_auth_type.get()}

            },
            "data_modification": {
                "api_url": self.dm_api_url_entry.get().strip(),
                "data_item_id": self.dm_data_id_entry.get().strip(),
                "new_value": self.dm_new_value_entry.get().strip(),
                "http_method": self.dm_method_type.get(),
                "request_body": self.safe_scrolledtext_get(self.dm_request_body_text),
                "custom_headers": self.safe_scrolledtext_get(self.dm_custom_headers_text),
                "auth_type": self.dm_auth_type.get(),
                "verify_url": self.safe_entry_get(self.dm_verify_url_entry),
                "auth_params": {
                    "auth_type": self.dm_auth_type.get(),
                    "username": self.safe_entry_get(getattr(self, 'dm_username_entry', None)) if include_credentials and self.dm_auth_type.get() == "Basic Auth" else "",
                    "password": self.safe_entry_get(getattr(self, 'dm_password_entry', None)) if include_credentials and self.dm_auth_type.get() == "Basic Auth" else "",
                    "header_name": self.safe_entry_get(getattr(self, 'dm_header_name_entry', None)) if include_credentials and self.dm_auth_type.get() == "API Key (Header)" else "",
                    "header_value": self.safe_entry_get(getattr(self, 'dm_header_value_entry', None)) if include_credentials and self.dm_auth_type.get() == "API Key (Header)" else "",
                    "token": self.safe_entry_get(getattr(self, 'dm_token_entry', None)) if include_credentials and self.dm_auth_type.get() == "Bearer Token" else ""
                } if include_credentials else {"auth_type": self.dm_auth_type.get()}
            }
        }

        if include_credentials:
            warning_message = "WARNING: You are saving settings that include sensitive credentials.\n\nThis saves usernames, passwords, API keys, and tokens in plain text within the JSON file. Ensure you store this file securely.\n\nDo you want to proceed?"
            if not messagebox.askyesno("Confirm Save with Credentials", warning_message):
                self.update_status("Save with credentials cancelled.")
                return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Settings As"
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(settings, f, indent=4)
                if include_credentials:
                    messagebox.showinfo("Settings Saved", f"Settings including credentials saved to {file_path}")
                    self.update_status(f"Settings with credentials saved to {os.path.basename(file_path)}")
                else:
                    messagebox.showinfo("Settings Saved", f"Settings saved to {file_path}\n(Note: Sensitive credentials were NOT saved.)")
                    self.update_status(f"Settings (no credentials) saved to {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save settings: {e}")
                self.queue_message(f"Error saving settings: {e}", 'error')
                self.update_status("Error saving settings")


    def load_settings(self, include_credentials=False):
        """Loads settings from a JSON file."""
        if include_credentials:
             warning_message = "WARNING: You are loading settings that may include sensitive credentials.\n\nThis will populate username, password, API key, and token fields. Ensure you trust the source of this file.\n\nDo you want to proceed?"
             if not messagebox.askyesno("Confirm Load with Credentials", warning_message):
                 self.update_status("Load with credentials cancelled.")
                 return


        file_path = filedialog.askopenfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Load Settings"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    settings = json.load(f)

                # Populate GUI fields
                general_settings = settings.get("general", {})
                self.base_url_entry.delete(0, tk.END)
                self.base_url_entry.insert(0, general_settings.get("base_url", ""))
                self.proxy_text.delete("1.0", tk.END)
                self.proxy_text.insert(tk.END, general_settings.get("proxies", ""))

                fl_settings = settings.get("failed_logins", {})
                self.failed_logins_url_entry.delete(0, tk.END)
                self.failed_logins_url_entry.insert(0, fl_settings.get("login_url", ""))
                if include_credentials:
                    self.failed_logins_username_entry.delete(0, tk.END)
                    self.failed_logins_username_entry.insert(0, fl_settings.get("username", ""))
                    self.failed_logins_password_prefix_entry.delete(0, tk.END)
                    self.failed_logins_password_prefix_entry.insert(0, fl_settings.get("password_prefix", ""))
                self.failed_logins_attempts_entry.delete(0, tk.END)
                self.failed_logins_attempts_entry.insert(0, fl_settings.get("num_attempts", "10"))
                self.update_tab_status("failed_logins", "Ready", "black")


                dt_settings = settings.get("directory_traversal", {})
                self.dt_target_path_entry.delete(0, tk.END)
                self.dt_target_path_entry.insert(0, dt_settings.get("target_path", "/"))
                self.dt_payloads_text.delete("1.0", tk.END)
                self.dt_payloads_text.insert(tk.END, dt_settings.get("payloads", "../\n../../\n..."))
                self.safe_scrolledtext_insert(self.dt_custom_headers_text, dt_settings.get("custom_headers", ""))
                dt_loaded_auth_type = dt_settings.get("auth_type", "None")
                self.dt_auth_type.set(dt_loaded_auth_type)
                self.update_dt_auth_fields()
                if include_credentials and dt_loaded_auth_type != "None":
                    auth_params_dt = dt_settings.get("auth_params", {})
                    if dt_loaded_auth_type == "Basic Auth":
                        self.safe_entry_insert(getattr(self, 'dt_username_entry', None), auth_params_dt.get("username", ""))
                        self.safe_entry_insert(getattr(self, 'dt_password_entry', None), auth_params_dt.get("password", ""))
                    elif dt_loaded_auth_type == "API Key (Header)":
                        self.safe_entry_insert(getattr(self, 'dt_header_name_entry', None), auth_params_dt.get("header_name", ""))
                        self.safe_entry_insert(getattr(self, 'dt_header_value_entry', None), auth_params_dt.get("header_value", ""))
                    elif dt_loaded_auth_type == "Bearer Token":
                        self.safe_entry_insert(getattr(self, 'dt_token_entry', None), auth_params_dt.get("token", ""))
                self.update_tab_status("directory_traversal", "Ready", "black")


                dm_settings = settings.get("data_modification", {})
                self.dm_api_url_entry.delete(0, tk.END)
                self.dm_api_url_entry.insert(0, dm_settings.get("api_url", ""))
                self.dm_data_id_entry.delete(0, tk.END)
                self.dm_data_id_entry.insert(0, dm_settings.get("data_item_id", ""))
                self.dm_new_value_entry.delete(0, tk.END)
                self.dm_new_value_entry.insert(0, dm_settings.get("new_value", ""))
                self.dm_method_type.set(dm_settings.get("http_method", "PUT"))
                self.safe_scrolledtext_insert(self.dm_request_body_text, dm_settings.get("request_body", ""))
                self.safe_scrolledtext_insert(self.dm_custom_headers_text, dm_settings.get("custom_headers", ""))
                dm_loaded_auth_type = dm_settings.get("auth_type", "None")
                self.dm_auth_type.set(dm_loaded_auth_type)
                self.update_dm_auth_fields()
                if include_credentials and dm_loaded_auth_type != "None":
                    auth_params_dm = dm_settings.get("auth_params", {})
                    if dm_loaded_auth_type == "Basic Auth":
                        self.safe_entry_insert(getattr(self, 'dm_username_entry', None), auth_params_dm.get("username", ""))
                        self.safe_entry_insert(getattr(self, 'dm_password_entry', None), auth_params_dm.get("password", ""))
                    elif dm_loaded_auth_type == "API Key (Header)":
                        self.safe_entry_insert(getattr(self, 'dm_header_name_entry', None), auth_params_dm.get("header_name", ""))
                        self.safe_entry_insert(getattr(self, 'dm_header_value_entry', None), auth_params_dm.get("header_value", ""))
                    elif dm_loaded_auth_type == "Bearer Token":
                        self.safe_entry_insert(getattr(self, 'dm_token_entry', None), auth_params_dm.get("token", ""))

                self.safe_entry_insert(self.dm_verify_url_entry, dm_settings.get("verify_url", ""))
                self.update_tab_status("data_modification", "Ready", "black")


                if include_credentials:
                    messagebox.showinfo("Settings Loaded", f"Settings including credentials loaded from {file_path}")
                    self.update_status(f"Settings with credentials loaded from {os.path.basename(file_path)}")
                else:
                    messagebox.showinfo("Settings Loaded", f"Settings loaded from {file_path}\n(Note: Sensitive credentials were NOT loaded and must be re-entered.)")
                    self.update_status(f"Settings (no credentials) loaded from {os.path.basename(file_path)}")

            except FileNotFoundError:
                 messagebox.showerror("Load Error", f"Settings file not found: {file_path}")
                 self.queue_message(f"Error loading settings: File not found: {file_path}", 'error')
                 self.update_status("Error loading settings: File not found")
                 self.update_tab_status("failed_logins", "Load Error", "red")
                 self.update_tab_status("directory_traversal", "Load Error", "red")
                 self.update_tab_status("data_modification", "Load Error", "red")

            except json.JSONDecodeError:
                 messagebox.showerror("Load Error", f"Invalid JSON format in settings file: {file_path}")
                 self.queue_message(f"Error loading settings: Invalid JSON in {file_path}", 'error')
                 self.update_status("Error loading settings: Invalid JSON")
                 self.update_tab_status("failed_logins", "Load Error", "red")
                 self.update_tab_status("directory_traversal", "Load Error", "red")
                 self.update_tab_status("data_modification", "Load Error", "red")

            except Exception as e:
                messagebox.showerror("Load Error", f"Failed to load settings: {e}")
                self.queue_message(f"Error loading settings: {e}", 'error')
                self.update_status("Error loading settings")
                self.update_tab_status("failed_logins", "Load Error", "red")
                self.update_tab_status("directory_traversal", "Load Error", "red")
                self.update_tab_status("data_modification", "Load Error", "red")


    def cancel_all_tests(self):
        """Sets a flag to signal all running test threads to stop."""
        if self.running_tests:
            self._stop_threads = True
            self.queue_message("Cancel signal sent to running tests...", 'warning')
            self.update_status("Cancel signal sent...")
            for test_name in self.running_tests.keys():
                 self.update_tab_status(test_name, "Cancelling...", "orange")

        else:
            self.queue_message("No tests are currently running.", 'info')
            self.update_status("No tests running to cancel.")

    def on_closing(self):
        """Handles window closing, ensuring threads are stopped."""
        if self.running_tests:
            if messagebox.askokcancel("Quit", "Tests are still running. Do you want to quit and stop them?"):
                self._stop_threads = True
                self.update_status("Stopping tests and quitting...")
                for test_name in self.running_tests.keys():
                     self.update_tab_status(test_name, "Stopping...", "red")
                self.master.after(500, self.master.destroy)
        else:
            self.master.destroy()


# --- Main Execution ---
if __name__ == "__main__":
    root = tk.Tk()
    gui = SecurityLoggingTesterGUI(root)
    root.mainloop()
