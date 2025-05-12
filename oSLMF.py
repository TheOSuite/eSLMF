import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
import threading
import time
import requests
import queue
import json
import os
import random
import base64
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse, urljoin

# Constants
TAB_FAILED_LOGINS = "failed_logins"
TAB_DIRECTORY_TRAVERSAL = "directory_traversal"
TAB_DATA_MODIFICATION = "data_modification"

TEST_FAILED_LOGINS = TAB_FAILED_LOGINS
TEST_DIRECTORY_TRAVERSAL = TAB_DIRECTORY_TRAVERSAL
TEST_DATA_MODIFICATION = TAB_DATA_MODIFICATION

SEVERITY_INFO = 'info'
SEVERITY_WARNING = 'warning'
SEVERITY_ERROR = 'error'
SEVERITY_SUCCESS = 'success'
SEVERITY_HEADER = 'header'

class SecurityLoggingTesterGUI:
    def __init__(self, master):
        self.master = master
        master.title("Security Logging Tester")

        # Initialize flag/dictionary to track running tests and their threads
        # Changed from False to {} to store thread references
        self.running_tests = {} # <--- Change this line

        # Initialize the flag used to signal threads to stop
        self._stop_threads = False # <--- Add this line

        # Initialize auth widget dictionaries BEFORE creating tabs
        self._dt_auth_widgets = {}
        self._dm_auth_widgets = {}

        # Initialize queue BEFORE any use
        self.queue = queue.Queue()

        # --- Status Bar ---
        self._status_message = tk.StringVar()
        self.status_bar = tk.Label(self.master, textvariable=self._status_message, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # --- Tab Status Variables ---
        self._fl_status = tk.StringVar(value="Ready")
        self._dt_status = tk.StringVar(value="Ready")
        self._dm_status = tk.StringVar(value="Ready")

        # --- Notebook ---
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Create tabs
        # NOTE: The status labels are created within these methods and assigned to self._fl_status_label, self._dt_status_label, self._dm_status_label
        self.create_general_tab()
        self.create_failed_logins_tab()
        self.create_directory_traversal_tab()
        self.create_data_modification_tab()

        # --- Output Area ---
        self.output_label = tk.Label(self.master, text="Output:")
        self.output_label.pack(pady=5)
        self.output_area = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, width=80, height=15)
        self.output_area.pack(padx=10, pady=5, fill="both", expand=True)
        self.output_area.config(state='disabled')

        # Tag configs
        self.output_area.tag_config(SEVERITY_INFO, foreground='black')
        self.output_area.tag_config(SEVERITY_WARNING, foreground='orange')
        self.output_area.tag_config(SEVERITY_ERROR, foreground='red')
        self.output_area.tag_config(SEVERITY_SUCCESS, foreground='green')
        self.output_area.tag_config(SEVERITY_HEADER, foreground='blue', font=('TkDefaultFont', 9, 'bold'))

        # Session
        self.session = self.create_session()
        self.proxy_list = []

        # Control buttons
        self.create_control_buttons()

        # Handle close
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Start queue processing
        self.master.after(100, self.process_queue)

    def create_session(self):
        s = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    # --- Tab creation with initial auth field setup ---

    def create_general_tab(self):
        self.general_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.general_tab, text="General")

        # --- Base URL ---
        self.base_url_label = tk.Label(self.general_tab, text="Base URL:")
        self.base_url_label.grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.base_url_entry = tk.Entry(self.general_tab, width=60)
        self.base_url_entry.grid(row=0, column=1, padx=5, pady=2)

        # --- Proxy Settings ---
        tk.Label(self.general_tab, text="Proxy List (host:port, one per line):").grid(row=1, column=0, sticky="nw", padx=5, pady=2)
        # Create the proxy_text widget and assign it to self.proxy_text
        self.proxy_text = scrolledtext.ScrolledText(self.general_tab, wrap=tk.WORD, width=50, height=5) # <--- Add this line
        self.proxy_text.grid(row=1, column=1, padx=5, pady=2, sticky="ew")

        # Proxy Load/Save Buttons
        proxy_button_frame = tk.Frame(self.general_tab)
        proxy_button_frame.grid(row=2, column=1, sticky="w", padx=5, pady=2) # Place below proxy_text
        load_proxy_button = tk.Button(proxy_button_frame, text="Load Proxies", command=self.load_proxies_from_file) # <--- Add this line
        load_proxy_button.pack(side=tk.LEFT, padx=5)
        save_proxy_button = tk.Button(proxy_button_frame, text="Save Proxies", command=self.save_proxies_to_file) # <--- Add this line
        save_proxy_button.pack(side=tk.LEFT, padx=5)

        # Configure grid weights to allow resizing
        self.general_tab.grid_columnconfigure(1, weight=1)
        self.general_tab.grid_rowconfigure(1, weight=1) # Allow proxy_text area to expand vertically

    def create_failed_logins_tab(self):
        self.failed_logins_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.failed_logins_tab, text="Failed Logins")
        self._fl_status_label = tk.Label(self.failed_logins_tab, textvariable=self._fl_status, font=('TkDefaultFont', 9, 'italic'))
        self._fl_status_label.grid(row=0, column=0, sticky="e", padx=5, pady=2)

        # URL
        tk.Label(self.failed_logins_tab, text="Login URL (full path):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.failed_logins_url_entry = tk.Entry(self.failed_logins_tab, width=60)
        self.failed_logins_url_entry.grid(row=1, column=1, padx=5, pady=2)

        # Username
        tk.Label(self.failed_logins_tab, text="Username:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.failed_logins_username_entry = tk.Entry(self.failed_logins_tab, width=30)
        self.failed_logins_username_entry.grid(row=2, column=1, padx=5, pady=2, sticky="w")

        # Password Prefix
        tk.Label(self.failed_logins_tab, text="Password Prefix:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.failed_logins_password_prefix_entry = tk.Entry(self.failed_logins_tab, width=30)
        self.failed_logins_password_prefix_entry.grid(row=3, column=1, padx=5, pady=2, sticky="w")
        
        # ID (new)
        tk.Label(self.failed_logins_tab, text="ID:").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        self.failed_logins_id_entry = tk.Entry(self.failed_logins_tab, width=30)
        self.failed_logins_id_entry.grid(row=4, column=1, padx=5, pady=2, sticky="w")
        
        # Attempts
        tk.Label(self.failed_logins_tab, text="Number of Attempts:").grid(row=5, column=0, sticky="w", padx=5, pady=2)
        self.failed_logins_attempts_entry = tk.Entry(self.failed_logins_tab, width=10)
        self.failed_logins_attempts_entry.grid(row=5, column=1, padx=5, pady=2, sticky="w")
        self.failed_logins_attempts_entry.insert(0, "10")

        # Run button
        self.run_failed_logins_button = tk.Button(self.failed_logins_tab, text="Run Failed Logins Test", command=self.run_failed_logins_thread)
        self.run_failed_logins_button.grid(row=6, column=0, columnspan=2, pady=10)
        # Progress bar
        self.failed_logins_progress = ttk.Progressbar(self.failed_logins_tab, orient="horizontal", length=400, mode="determinate")
        self.failed_logins_progress.grid(row=7, column=0, columnspan=2, pady=5, sticky="ew")
        self.failed_logins_progress.grid_forget()

    def create_directory_traversal_tab(self):
        self.directory_traversal_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.directory_traversal_tab, text="Directory Traversal")
        self._dt_status_label = tk.Label(self.directory_traversal_tab, textvariable=self._dt_status, font=('TkDefaultFont', 9, 'italic'))
        self._dt_status_label.grid(row=0, column=0, sticky="e", padx=5, pady=2)

        # Path
        tk.Label(self.directory_traversal_tab, text="Target Path (relative to Base URL):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.dt_target_path_entry = tk.Entry(self.directory_traversal_tab, width=60)
        self.dt_target_path_entry.grid(row=1, column=1, padx=5, pady=2)
        self.dt_target_path_entry.insert(0, "/")

        # Payloads
        tk.Label(self.directory_traversal_tab, text="Traversal Payloads (one per line):").grid(row=2, column=0, sticky="nw", padx=5, pady=2)
        self.dt_payloads_text = scrolledtext.ScrolledText(self.directory_traversal_tab, wrap=tk.WORD, width=50, height=5)
        self.dt_payloads_text.grid(row=2, column=1, padx=5, pady=2)
        self.dt_payloads_text.insert(tk.END, "../\n../../\n../../../\n%2e%2e%2f\n%2e%2e/\n.././../\n..\;/")

        # Custom headers
        tk.Label(self.directory_traversal_tab, text="Custom Headers (Name: Value, one per line):").grid(row=4, column=0, sticky="nw", padx=5, pady=2)
        self.dt_custom_headers_text = scrolledtext.ScrolledText(self.directory_traversal_tab, wrap=tk.WORD, width=50, height=4)
        self.dt_custom_headers_text.grid(row=4, column=1, padx=5, pady=2)

        # Auth dropdown & frame
        tk.Label(self.directory_traversal_tab, text="Authentication:").grid(row=5, column=0, sticky="w", padx=5, pady=2)
        self.dt_auth_type = tk.StringVar(value="None")
        self.dt_auth_dropdown = ttk.Combobox(self.directory_traversal_tab, textvariable=self.dt_auth_type,
                                             values=["None", "Basic Auth", "API Key (Header)", "Bearer Token"],
                                             state="readonly")
        self.dt_auth_dropdown.grid(row=5, column=1, sticky="w", padx=5, pady=2)
        self.dt_auth_dropdown.bind("<<ComboboxSelected>>", lambda e: self.update_auth_fields(self.dt_auth_fields_frame, self.dt_auth_type, "_dt", self._dt_auth_widgets))
        self.dt_auth_fields_frame = tk.Frame(self.directory_traversal_tab)
        self.dt_auth_fields_frame.grid(row=6, column=0, columnspan=2, sticky="ew", padx=5, pady=2)
        # Initialize auth fields
        self.update_auth_fields(self.dt_auth_fields_frame, self.dt_auth_type, "_dt", self._dt_auth_widgets)

        # Run button
        self.run_directory_traversal_button = tk.Button(self.directory_traversal_tab, text="Run Directory Traversal Test", command=self.run_directory_traversal_thread)
        self.run_directory_traversal_button.grid(row=7, column=0, columnspan=2, pady=10)
        self.dt_progress = ttk.Progressbar(self.directory_traversal_tab, orient="horizontal", length=400, mode="determinate")
        self.dt_progress.grid(row=8, column=0, columnspan=2, pady=5, sticky="ew")
        self.dt_progress.grid_forget()

    def create_data_modification_tab(self):
        self.data_modification_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.data_modification_tab, text="Data Modification")
        self._dm_status_label = tk.Label(self.data_modification_tab, textvariable=self._dm_status, font=('TkDefaultFont', 9, 'italic'))
        self._dm_status_label.grid(row=0, column=0, sticky="e", padx=5, pady=2)

        # URL, Data ID, New Value, Method, etc.
        tk.Label(self.data_modification_tab, text="API URL (full path):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.dm_api_url_entry = tk.Entry(self.data_modification_tab, width=60)
        self.dm_api_url_entry.grid(row=1, column=1, padx=5, pady=2)

        tk.Label(self.data_modification_tab, text="Data ID (in URL or body):").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.dm_data_id_entry = tk.Entry(self.data_modification_tab, width=30)
        self.dm_data_id_entry.grid(row=2, column=1, padx=5, pady=2, sticky="w")

        tk.Label(self.data_modification_tab, text="New Value (used in body if no Request Body):").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.dm_new_value_entry = tk.Entry(self.data_modification_tab, width=30)
        self.dm_new_value_entry.grid(row=3, column=1, padx=5, pady=2, sticky="w")

        tk.Label(self.data_modification_tab, text="HTTP Method:").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        self.dm_method_type = tk.StringVar(value="PUT")
        self.dm_method_dropdown = ttk.Combobox(self.data_modification_tab, textvariable=self.dm_method_type, values=["GET", "POST", "PUT", "PATCH", "DELETE"], state="readonly")
        self.dm_method_dropdown.grid(row=4, column=1, sticky="w", padx=5, pady=2)

        tk.Label(self.data_modification_tab, text="Request Body (JSON, optional):").grid(row=5, column=0, sticky="nw", padx=5, pady=2)
        self.dm_request_body_text = scrolledtext.ScrolledText(self.data_modification_tab, wrap=tk.WORD, width=60, height=8)
        self.dm_request_body_text.grid(row=5, column=1, padx=5, pady=2)

        tk.Label(self.data_modification_tab, text="Custom Headers (Name: Value, one per line):").grid(row=6, column=0, sticky="nw", padx=5, pady=2)
        self.dm_custom_headers_text = scrolledtext.ScrolledText(self.data_modification_tab, wrap=tk.WORD, width=60, height=4)
        self.dm_custom_headers_text.grid(row=6, column=1, padx=5, pady=2)

        # Auth dropdown
        tk.Label(self.data_modification_tab, text="Authentication:").grid(row=7, column=0, sticky="w", padx=5, pady=2)
        self.dm_auth_type = tk.StringVar(value="None")
        self.dm_auth_dropdown = ttk.Combobox(self.data_modification_tab, textvariable=self.dm_auth_type,
                                             values=["None", "Basic Auth", "API Key (Header)", "Bearer Token"],
                                             state="readonly")
        self.dm_auth_dropdown.grid(row=7, column=1, sticky="w", padx=5, pady=2)
        self.dm_auth_dropdown.bind("<<ComboboxSelected>>", lambda e: self.update_auth_fields(self.dm_auth_fields_frame, self.dm_auth_type, "_dm", self._dm_auth_widgets))
        self.dm_auth_fields_frame = tk.Frame(self.data_modification_tab)
        self.dm_auth_fields_frame.grid(row=8, column=0, columnspan=2, sticky="ew", padx=5, pady=2)
        # Initialize auth fields
        self.update_auth_fields(self.dm_auth_fields_frame, self.dm_auth_type, "_dm", self._dm_auth_widgets)

        # Verify URL
        tk.Label(self.data_modification_tab, text="Verification URL (Optional):").grid(row=9, column=0, sticky="w", padx=5, pady=2)
        self.dm_verify_url_entry = tk.Entry(self.data_modification_tab, width=60)
        self.dm_verify_url_entry.grid(row=9, column=1, padx=5, pady=2)

        # Run button
        self.run_data_modification_button = tk.Button(self.data_modification_tab, text="Run Data Modification Test", command=self.run_data_modification_thread)
        self.run_data_modification_button.grid(row=10, column=0, columnspan=2, pady=10)

        # Progress
        self.dm_progress = ttk.Progressbar(self.data_modification_tab, orient="horizontal", length=400, mode="determinate")
        self.dm_progress.grid(row=11, column=0, columnspan=2, pady=5, sticky="ew")
        self.dm_progress.grid_forget()

    # --- update_auth_fields method ---
    def update_auth_fields(self, frame, auth_type_var, prefix, widget_dict, event=None):
        for widget in frame.winfo_children():
            widget.destroy()
        widget_dict.clear()

        auth_type = auth_type_var.get()

        if auth_type == "Basic Auth":
            widget_dict[f"{prefix}_username"] = tk.Entry(frame, width=30)
            tk.Label(frame, text="Username:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
            widget_dict[f"{prefix}_username"].grid(row=0, column=1, sticky="w", padx=5, pady=2)

            widget_dict[f"{prefix}_password"] = tk.Entry(frame, width=30, show="*")
            tk.Label(frame, text="Password:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
            widget_dict[f"{prefix}_password"].grid(row=1, column=1, sticky="w", padx=5, pady=2)

        elif auth_type == "API Key (Header)":
            widget_dict[f"{prefix}_header_name"] = tk.Entry(frame, width=30)
            tk.Label(frame, text="Header Name:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
            widget_dict[f"{prefix}_header_name"].grid(row=0, column=1, sticky="w", padx=5, pady=2)

            widget_dict[f"{prefix}_header_value"] = tk.Entry(frame, width=30)
            tk.Label(frame, text="Header Value:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
            widget_dict[f"{prefix}_header_value"].grid(row=1, column=1, sticky="w", padx=5, pady=2)

        elif auth_type == "Bearer Token":
            widget_dict[f"{prefix}_token"] = tk.Entry(frame, width=60)
            tk.Label(frame, text="Token:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
            widget_dict[f"{prefix}_token"].grid(row=0, column=1, sticky="w", padx=5, pady=2)

        if auth_type != "None":
            frame.grid()
        else:
            frame.grid_forget()

    # --- Control Buttons (Unchanged structure) ---

    def create_control_buttons(self):
        """Creates buttons for saving/loading settings and canceling tests."""
        control_frame = tk.Frame(self.master)
        control_frame.pack(pady=10)

        save_button = tk.Button(control_frame, text="Save Settings (No Credentials)", command=lambda: self.save_settings(include_credentials=False))
        save_button.pack(side=tk.LEFT, padx=5)

        load_button = tk.Button(control_frame, text="Load Settings (No Credentials)", command=lambda: self.load_settings(include_credentials=False))
        load_button.pack(side=tk.LEFT, padx=5)

        ttk.Separator(control_frame, orient='vertical').pack(side=tk.LEFT, padx=10, fill='y')

        # Highlight the risk of saving credentials
        save_creds_button = tk.Button(control_frame, text="Save Settings (Include Credentials)", command=lambda: self.save_settings(include_credentials=True), fg="red")
        save_creds_button.pack(side=tk.LEFT, padx=5)

        load_creds_button = tk.Button(control_frame, text="Load Settings (Include Credentials)", command=lambda: self.load_settings(include_credentials=True), fg="red")
        load_creds_button.pack(side=tk.LEFT, padx=5)

        ttk.Separator(control_frame, orient='vertical').pack(side=tk.LEFT, padx=10, fill='y')

        cancel_button = tk.Button(control_frame, text="Cancel All Tests", command=self.cancel_all_tests)
        self.cancel_button = cancel_button # Keep a reference to the cancel button
        cancel_button.pack(side=tk.LEFT, padx=5)

    # --- Thread-Safe GUI Update Methods ---

    def queue_message(self, message, severity=SEVERITY_INFO):
        """Adds a message with severity to the queue for output area update."""
        self.queue.put(('output', message, severity))

    def queue_update_status(self, message):
        """Adds a message to the queue for main status bar update."""
        self.queue.put(('status', message))

    def queue_update_tab_status(self, tab_name, message, color=None):
        """Adds a message to the queue for specific tab status label update."""
        self.queue.put(('tab_status', tab_name, message, color))

    def queue_update_progress(self, tab_name, value):
        """Adds a value to the queue for specific tab progress bar update."""
        self.queue.put(('progress_update', tab_name, value))

    def queue_reset_progress(self, tab_name):
         """Adds a command to reset the progress bar for a specific tab."""
         self.queue.put(('progress_reset', tab_name))

    def queue_enable_button(self, button_widget):
        """Adds a command to enable a button widget."""
        self.queue.put(('enable_widget', button_widget))

    def queue_disable_button(self, button_widget):
        """Adds a command to disable a button widget."""
        self.queue.put(('disable_widget', button_widget))

    def process_queue(self):
        """Processes messages from the queue and updates the GUI."""
        try:
            while True:
                item = self.queue.get_nowait()
                item_type = item[0]

                if item_type == 'output':
                    _, message, severity = item
                    self._update_output_gui(message, severity)
                elif item_type == 'status':
                    _, message = item
                    self._update_status_gui(message)
                elif item_type == 'tab_status':
                    _, tab_name, message, color = item
                    self._update_tab_status_gui(tab_name, message, color)
                elif item_type == 'progress_update':
                    _, tab_name, value = item
                    self._update_progress_gui(tab_name, value)
                elif item_type == 'progress_reset':
                    _, tab_name = item
                    self._reset_progress_gui(tab_name)
                elif item_type == 'enable_widget':
                    _, widget = item
                    self._enable_widget_gui(widget)
                elif item_type == 'disable_widget':
                    _, widget = item
                    self._disable_widget_gui(widget)

        except queue.Empty:
            pass
        finally:
            self.master.after(100, self.process_queue) # Schedule the next check

    # --- Actual GUI Update Methods (Called ONLY by process_queue) ---

    def _update_output_gui(self, message, severity):
        self.output_area.config(state='normal')
        self.output_area.insert(tk.END, message + "\n", severity)
        self.output_area.see(tk.END)
        self.output_area.config(state='disabled')

    def _update_status_gui(self, message):
        self._status_message.set(message)

    def _update_tab_status_gui(self, tab_name, message, color=None):
        """Updates the status label for a specific tab."""
        status_label = None
        if tab_name == TAB_FAILED_LOGINS:
            self._fl_status.set(message)
            # Corrected attribute name
            status_label = self._fl_status_label # <--- Added underscore
        elif tab_name == TAB_DIRECTORY_TRAVERSAL:
            self._dt_status.set(message)
            # Corrected attribute name
            status_label = self._dt_status_label # <--- Added underscore
        elif tab_name == TAB_DATA_MODIFICATION:
            self._dm_status.set(message)
            # Corrected attribute name
            status_label = self._dm_status_label # <--- Added underscore

        if status_label:
            if color:
                 status_label.config(fg=color)
            else:
                 status_label.config(fg="black")

    def _update_progress_gui(self, tab_name, value):
        progressbar = None
        if tab_name == TAB_FAILED_LOGINS:
            progressbar = self.failed_logins_progress
        elif tab_name == TAB_DIRECTORY_TRAVERSAL:
            progressbar = self.dt_progress
        elif tab_name == TAB_DATA_MODIFICATION:
            progressbar = self.dm_progress

        if progressbar:
            progressbar.grid() # Ensure it's visible
            progressbar['value'] = value

    def _reset_progress_gui(self, tab_name):
        progressbar = None
        if tab_name == TAB_FAILED_LOGINS:
            progressbar = self.failed_logins_progress
        elif tab_name == TAB_DIRECTORY_TRAVERSAL:
            progressbar = self.dt_progress
        elif tab_name == TAB_DATA_MODIFICATION:
            progressbar = self.dm_progress

        if progressbar:
             progressbar['value'] = 0
             progressbar.grid_forget() # Hide it

    def _enable_widget_gui(self, widget):
        if widget:
            widget.config(state='normal')

    def _disable_widget_gui(self, widget):
        if widget:
            widget.config(state='disabled')

    # --- Data Handling (Proxies, Payloads, Settings) ---

    def get_proxies(self):
        """Retrieves and formats the list of proxies from the text area."""
        proxy_text = self.proxy_text.get("1.0", tk.END).strip()
        self.proxy_list = [line.strip() for line in proxy_text.splitlines() if line.strip()]
        return self.proxy_list

    def get_random_proxy(self):
        """Returns a randomly selected proxy dictionary or None if no proxies are configured."""
        proxies = self.get_proxies()
        if proxies:
            try:
                proxy_url = random.choice(proxies)
                # Validate the proxy URL format slightly
                if "://" not in proxy_url:
                    proxy_url = "http://" + proxy_url # Assume http if no scheme
                return {"http": proxy_url, "https": proxy_url}
            except IndexError:
                # Should not happen if proxies list is not empty, but good practice
                self.queue_message("Error: Proxy list is unexpectedly empty.", SEVERITY_ERROR)
                self.queue_update_status("Error selecting proxy")
                return None
            except Exception as e:
                 # Catch potential errors in urlparse or other issues
                 self.queue_message(f"Error formatting proxy URL: {e}", SEVERITY_ERROR)
                 self.queue_update_status("Error formatting proxy URL")
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
                self.queue_message(f"Proxies loaded from {os.path.basename(file_path)}", SEVERITY_INFO)
                self.queue_update_status(f"Proxies loaded from {os.path.basename(file_path)}")
            except FileNotFoundError:
                messagebox.showerror("Load Error", f"Proxy file not found: {file_path}")
                self.queue_message(f"Error loading proxies: File not found: {file_path}", SEVERITY_ERROR)
                self.queue_update_status("Error loading proxies")
            except Exception as e:
                messagebox.showerror("Load Error", f"Failed to load proxies: {e}")
                self.queue_message(f"Error loading proxies: {e}", SEVERITY_ERROR)
                self.queue_update_status("Error loading proxies")

    def save_proxies_to_file(self):
        """Saves current proxy list to a text file."""
        proxies = self.proxy_text.get("1.0", tk.END).strip()
        if not proxies:
            messagebox.showwarning("No Proxies", "There are no proxies to save.")
            self.queue_update_status("No proxies to save")
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
                self.queue_message(f"Proxies saved to {os.path.basename(file_path)}", SEVERITY_INFO)
                self.queue_update_status(f"Proxies saved to {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save proxies: {e}")
                self.queue_message(f"Error saving proxies: {e}", SEVERITY_ERROR)
                self.queue_update_status("Error saving proxies")

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
                self.queue_message(f"Directory traversal payloads loaded from {os.path.basename(file_path)}", SEVERITY_INFO)
                self.queue_update_status(f"DT Payloads loaded from {os.path.basename(file_path)}")
            except FileNotFoundError:
                messagebox.showerror("Load Error", f"Payload file not found: {file_path}")
                self.queue_message(f"Error loading payloads: File not found: {file_path}", SEVERITY_ERROR)
                self.queue_update_status("Error loading DT payloads: File not found")
            except Exception as e:
                messagebox.showerror("Load Error", f"Failed to load payloads: {e}")
                self.queue_message(f"Error loading payloads: {e}", SEVERITY_ERROR)
                self.queue_update_status("Error loading DT payloads")

    # --- Validation and Parsing ---

    def validate_url(self, url):
        """Basic URL validation, requires scheme and netloc."""
        if not url:
            return False
        try:
            result = urlparse(url)
            # Require both scheme and netloc for better validation
            return result.scheme in ['http', 'https'] and result.netloc
        except Exception as e:
            print(f"URL validation error for '{url}': {e}") # Print to console for debug
            return False

    def normalize_url(self, url):
        """Ensures URL has a scheme, defaults to http if missing but netloc exists."""
        if not url:
            return ""
        parsed = urlparse(url)
        if not parsed.scheme and parsed.netloc:
            return "http://" + url # Default to http if no scheme but has a domain/IP
        # Optionally: default to https if no scheme but has a domain/IP? Depends on common usage.
        # For now, sticking to http as the non-secure default.
        return url

    def safe_entry_get(self, entry_widget):
        """Safely gets text from an Entry widget, returning '' if the widget doesn't exist."""
        try:
            # Check if the widget exists and is not destroyed
            if entry_widget and entry_widget.winfo_exists():
                return entry_widget.get().strip()
            return ""
        except AttributeError:
             return "" # Handle cases where entry_widget might be None or an unexpected type
        except tk.TclError:
             return "" # Handle cases where the widget might be destroyed

    def safe_entry_insert(self, entry_widget, value):
        """Safely inserts text into an Entry widget, handling potential issues."""
        try:
            if entry_widget and entry_widget.winfo_exists():
                entry_widget.delete(0, tk.END)
                entry_widget.insert(0, value)
            # else: print(f"Warning: Attempted to insert into non-existent widget {entry_widget}") # Optional debug
        except AttributeError:
             pass
        except tk.TclError:
             pass # Widget might be destroyed

    def safe_scrolledtext_get(self, text_widget):
        """Safely gets text from a ScrolledText widget, returning '' if the widget doesn't exist."""
        try:
            if text_widget and text_widget.winfo_exists():
                 return text_widget.get("1.0", tk.END).strip()
            return ""
        except AttributeError:
             return ""
        except tk.TclError:
             return ""

    def safe_scrolledtext_insert(self, text_widget, value):
        """Safely inserts text into a ScrolledText widget, handling potential issues."""
        try:
            if text_widget and text_widget.winfo_exists():
                text_widget.delete("1.0", tk.END)
                text_widget.insert(tk.END, value)
            # else: print(f"Warning: Attempted to insert into non-existent text widget {text_widget}") # Optional debug
        except AttributeError:
             pass
        except tk.TclError:
             pass # Widget might be destroyed


    def parse_headers_string(self, headers_string):
        """Parses a string of headers (one per line, 'Name: Value') into a dictionary."""
        headers = {}
        if not headers_string:
            return headers
        for line in headers_string.splitlines():
            line = line.strip()
            if line: # Process non-empty lines
                if ':' in line:
                    try:
                        name, value = line.split(':', 1)
                        headers[name.strip()] = value.strip()
                    except Exception as e:
                        # More specific warning for parsing issues
                        self.queue_message(f"Warning: Could not parse header line '{line}': {e}", SEVERITY_WARNING)
                else:
                    # Warn about lines that look like they should be headers but aren't
                    self.queue_message(f"Warning: Skipping potentially malformed header line '{line}' (missing ':').", SEVERITY_WARNING)

        return headers

    def get_auth_params_from_gui(self, tab_name):
        """Collects authentication parameters from the GUI for a specific tab."""
        auth_params = {"auth_type": "None"}
        widget_dict = {} # Default empty dict

        if tab_name == TAB_DIRECTORY_TRAVERSAL:
            auth_params["auth_type"] = self.dt_auth_type.get()
            widget_dict = self._dt_auth_widgets
            prefix = "_dt"
        elif tab_name == TAB_DATA_MODIFICATION:
            auth_params["auth_type"] = self.dm_auth_type.get()
            widget_dict = self._dm_auth_widgets
            prefix = "_dm"
        else:
            return auth_params # No auth for other tabs

        auth_type = auth_params["auth_type"]

        if auth_type == "Basic Auth":
            auth_params["username"] = self.safe_entry_get(widget_dict.get(f"{prefix}_username_entry"))
            auth_params["password"] = self.safe_entry_get(widget_dict.get(f"{prefix}_password_entry"))
        elif auth_type == "API Key (Header)":
            auth_params["header_name"] = self.safe_entry_get(widget_dict.get(f"{prefix}_header_name_entry"))
            auth_params["header_value"] = self.safe_entry_get(widget_dict.get(f"{prefix}_header_value_entry"))
        elif auth_type == "Bearer Token":
            auth_params["token"] = self.safe_entry_get(widget_dict.get(f"{prefix}_token_entry"))

        return auth_params

    def set_auth_params_in_gui(self, tab_name, auth_params):
        """Sets authentication parameters in the GUI for a specific tab."""
        if not auth_params:
            return

        auth_type = auth_params.get("auth_type", "None")
        widget_dict = {}
        auth_type_var = None
        prefix = ""
        auth_dropdown = None
        auth_frame = None

        if tab_name == TAB_DIRECTORY_TRAVERSAL:
            auth_type_var = self.dt_auth_type
            widget_dict = self._dt_auth_widgets
            prefix = "_dt"
            auth_dropdown = self.dt_auth_dropdown
            auth_frame = self.dt_auth_fields_frame
        elif tab_name == TAB_DATA_MODIFICATION:
            auth_type_var = self.dm_auth_type
            widget_dict = self._dm_auth_widgets
            prefix = "_dm"
            auth_dropdown = self.dm_auth_dropdown
            auth_frame = self.dm_auth_fields_frame
        else:
            return # No auth for other tabs

        # Temporarily set the auth type to trigger widget creation
        auth_type_var.set(auth_type)
        # Manually trigger the update logic instead of relying on the bind event
        self.update_auth_fields(auth_frame, auth_type_var, prefix, widget_dict)


        if auth_type == "Basic Auth":
            self.safe_entry_insert(widget_dict.get(f"{prefix}_username_entry"), auth_params.get("username", ""))
            self.safe_entry_insert(widget_dict.get(f"{prefix}_password_entry"), auth_params.get("password", ""))
        elif auth_type == "API Key (Header)":
            self.safe_entry_insert(widget_dict.get(f"{prefix}_header_name_entry"), auth_params.get("header_name", ""))
            self.safe_entry_insert(widget_dict.get(f"{prefix}_header_value_entry"), auth_params.get("header_value", ""))
        elif auth_type == "Bearer Token":
            self.safe_entry_insert(widget_dict.get(f"{prefix}_token_entry"), auth_params.get("token", ""))

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

    # --- Test Execution Threads (Modified to use queue for GUI updates) ---

    def run_failed_logins_thread(self):
        # --- Input Validation (remains in GUI thread) ---
        login_url = self.failed_logins_url_entry.get().strip()
        username = self.failed_logins_username_entry.get().strip()
        password_prefix = self.failed_logins_password_prefix_entry.get().strip()

        normalized_login_url = self.normalize_url(login_url)

        if not self.validate_url(normalized_login_url):
             messagebox.showerror("Invalid Input", "Please enter a valid Login URL (must include http:// or https:// and domain).")
             self.queue_update_status("Invalid Login URL")
             self.queue_update_tab_status(TEST_FAILED_LOGINS, "Validation Error", "red")
             return
        if not username or not password_prefix:
             messagebox.showwarning("Missing Input", "Please fill in Username and Password Prefix for failed logins.")
             self.queue_update_status("Missing Failed Login parameters")
             self.queue_update_tab_status(TEST_FAILED_LOGINS, "Missing Input", "red")
             return

        try:
            num_attempts = int(self.failed_logins_attempts_entry.get())
            if num_attempts <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Input", "Number of attempts must be a positive integer.")
            self.queue_update_status("Invalid Number of Attempts")
            self.queue_update_tab_status(TEST_FAILED_LOGINS, "Validation Error", "red")
            return

        # --- Prepare and Start Thread ---
        self.queue_disable_button(self.run_failed_logins_button)
        self.failed_logins_progress.config(mode="determinate", maximum=num_attempts, value=0) # Configure progress bar
        self.queue_update_progress(TEST_FAILED_LOGINS, 0) # Show and reset progress bar via queue

        self.queue_message(f"--- Starting {TEST_FAILED_LOGINS.replace('_', ' ').title()} Test ---", SEVERITY_HEADER)
        self.queue_update_status(f"Running {TEST_FAILED_LOGINS.replace('_', ' ').title()} Test...")
        self.queue_update_tab_status(TEST_FAILED_LOGINS, "Running...", "blue")

        thread_name = TEST_FAILED_LOGINS
        thread = threading.Thread(target=self.perform_failed_logins_test, args=(normalized_login_url, username, password_prefix, num_attempts, thread_name))
        self.running_tests[thread_name] = thread
        thread.start()

    def perform_failed_logins_test(self, url, username, password_prefix, num_attempts, test_name):
        cancelled = False
        try:
            for i in range(num_attempts):
                if self._stop_threads:
                    cancelled = True
                    break

                incorrect_password = f"{password_prefix}{i+1}"
                self.queue_message(f"Attempt {i+1}/{num_attempts}: Trying password '{incorrect_password}'...", SEVERITY_INFO)
                self.queue_update_status(f"Failed Logins: Attempt {i+1}/{num_attempts}")
                self.queue_update_progress(test_name, i + 1) # Update progress via queue


                try:
                    proxies = self.get_random_proxy() # Use get_random_proxy here
                    # Use data parameter for form submission
                    response = self.session.post(url, data={'username': username, 'password': incorrect_password}, timeout=10, proxies=proxies)
                    status_code = response.status_code
                    self.queue_message(f"  Response Status Code: {status_code}", SEVERITY_INFO) # Clarified message

                    # Check for status codes that might indicate failed login
                    if response.status_code in [401, 403]:
                         self.queue_message("  Likely authentication/authorization failure detected.", SEVERITY_SUCCESS) # Mark as success for finding the failure
                    elif 200 <= response.status_code < 300:
                         # Note: A 2xx status code *could* indicate success, which is unexpected for a *failed* login test.
                         # This might warrant investigation by the user.
                         self.queue_message("  Warning: Received a 2xx status code. This might indicate unexpected login success or a different endpoint behavior.", SEVERITY_WARNING)
                    else:
                         # Other status codes might also indicate failure or other issues
                         self.queue_message(f"  Received status code {status_code}.", SEVERITY_INFO)

                except requests.exceptions.ConnectTimeout:
                    self.queue_message(f"  Request timed out connecting to {url}", SEVERITY_ERROR)
                except requests.exceptions.ReadTimeout:
                     self.queue_message(f"  Request timed out reading from {url}", SEVERITY_ERROR)
                except requests.exceptions.ConnectionError as e:
                    self.queue_message(f"  Connection Error: {e}", SEVERITY_ERROR)
                except requests.exceptions.RequestException as e:
                    self.queue_message(f"  Request failed: {e}", SEVERITY_ERROR)
                except Exception as e:
                    # Catch any other unexpected errors during the request
                    self.queue_message(f"  An unexpected error occurred during the request: {e}", SEVERITY_ERROR)

                # Add a small delay between attempts to avoid overwhelming the server
                time.sleep(0.1) # Sleep for 100 milliseconds

            if not cancelled:
                 self.queue_message("--- Failed Logins Test Completed ---", SEVERITY_HEADER)
                 self.queue_update_status("Failed Logins Test Completed")
                 self.queue_update_tab_status(test_name, "Completed", "green")

        except Exception as e:
            # Catch any unexpected errors in the test logic itself
            self.queue_message(f"An unexpected error occurred during the {test_name} test: {e}", SEVERITY_ERROR)
            self.queue_update_status(f"Error during {test_name} test")
            self.queue_update_tab_status(test_name, "Error", "red")
            cancelled = True # Mark as cancelled due to error

        finally:
            # Ensure GUI elements are reset and buttons re-enabled via the queue
            self.queue_reset_progress(test_name)
            self.queue_enable_button(self.run_failed_logins_button)
            if cancelled:
                 self.queue_message(f"--- {test_name.replace('_', ' ').title()} Test Cancelled ---", SEVERITY_HEADER)
                 self.queue_update_tab_status(test_name, "Cancelled", "orange")
                 self.queue_update_status(f"{test_name.replace('_', ' ').title()} Test Cancelled")

            # Remove the test from the running list
            if test_name in self.running_tests:
                del self.running_tests[test_name]
            if not self.running_tests:
                 self.queue_update_status("Ready") # Update main status if no tests are running

    def run_directory_traversal_thread(self):
        # --- Input Validation (remains in GUI thread) ---
        base_url = self.base_url_entry.get().strip()
        target_path = self.dt_target_path_entry.get().strip()
        payloads_string = self.dt_payloads_text.get("1.0", tk.END).strip()
        custom_headers_string = self.dt_custom_headers_text.get("1.0", tk.END).strip()
        auth_params = self.get_auth_params_from_gui(TEST_DIRECTORY_TRAVERSAL)

        normalized_base_url = self.normalize_url(base_url)

        if not self.validate_url(normalized_base_url):
             messagebox.showerror("Invalid Input", "Please enter a valid Base URL (must include http:// or https:// and domain).")
             self.queue_update_status("Invalid Base URL")
             self.queue_update_tab_status(TEST_DIRECTORY_TRAVERSAL, "Validation Error", "red")
             return

        if not payloads_string:
             messagebox.showwarning("Missing Input", "Please provide directory traversal payloads.")
             self.queue_update_status("Missing DT payloads")
             self.queue_update_tab_status(TEST_DIRECTORY_TRAVERSAL, "Missing Input", "red")
             return

        payloads = [line.strip() for line in payloads_string.splitlines() if line.strip()]
        if not payloads:
             messagebox.showwarning("Missing Input", "No valid payloads found after parsing.")
             self.queue_update_status("No valid DT payloads")
             self.queue_update_tab_status(TEST_DIRECTORY_TRAVERSAL, "Missing Input", "red")
             return

        custom_headers = self.parse_headers_string(custom_headers_string)

        # --- Prepare and Start Thread ---
        self.queue_disable_button(self.run_directory_traversal_button)
        self.dt_progress.config(mode="determinate", maximum=len(payloads), value=0) # Configure progress bar
        self.queue_update_progress(TEST_DIRECTORY_TRAVERSAL, 0) # Show and reset progress bar via queue


        self.queue_message(f"--- Starting {TEST_DIRECTORY_TRAVERSAL.replace('_', ' ').title()} Test ---", SEVERITY_HEADER)
        self.queue_update_status(f"Running {TEST_DIRECTORY_TRAVERSAL.replace('_', ' ').title()} Test...")
        self.queue_update_tab_status(TEST_DIRECTORY_TRAVERSAL, "Running...", "blue")

        thread_name = TEST_DIRECTORY_TRAVERSAL
        thread = threading.Thread(target=self.perform_directory_traversal_test, args=(normalized_base_url, target_path, payloads, custom_headers, auth_params, thread_name))
        self.running_tests[thread_name] = thread
        thread.start()


    def perform_directory_traversal_test(self, base_url, target_path, payloads, custom_headers, auth_params, test_name):
        cancelled = False
        auth_arg, auth_headers = self.get_auth_headers(auth_params)
        combined_headers = {**custom_headers, **auth_headers} # Combine custom and auth headers

        try:
            for i, payload in enumerate(payloads):
                if self._stop_threads:
                    cancelled = True
                    break

                # Construct the URL with payload
                # Ensure correct path joining, handling potential leading/trailing slashes
                if not base_url.endswith('/') and not target_path.startswith('/'):
                    url = urljoin(base_url, '/' + target_path + payload)
                elif base_url.endswith('/') and target_path.startswith('/'):
                     url = urljoin(base_url, target_path[1:] + payload)
                else:
                    url = urljoin(base_url, target_path + payload)


                message = f"Testing payload '{payload}': {url}"
                self.queue_message(message, SEVERITY_INFO)
                self.queue_update_status(f"DT: Testing payload {i+1}/{len(payloads)}")
                self.queue_update_progress(test_name, i + 1) # Update progress via queue


                try:
                    proxies = self.get_random_proxy()
                    # Use the session created in __init__
                    response = self.session.get(url, headers=combined_headers, auth=auth_arg, timeout=10, proxies=proxies)
                    status_code = response.status_code
                    self.queue_message(f"  Response Status Code: {status_code}", SEVERITY_INFO)

                    # Basic check: 200 OK might indicate successful traversal
                    # A real test would also check response content for sensitive information
                    if status_code == 200:
                         self.queue_message("  Warning: Received 200 OK. This might indicate successful directory traversal.", SEVERITY_WARNING) # Changed to warning
                    elif status_code in [403, 404]:
                        self.queue_message(f"  Received {status_code}. Likely blocked or not found (as expected).", SEVERITY_SUCCESS) # Mark as success for security control
                    else:
                        self.queue_message(f"  Received status code {status_code}.", SEVERITY_INFO)

                except requests.exceptions.ConnectTimeout:
                    self.queue_message(f"  Request timed out connecting to {url}", SEVERITY_ERROR)
                except requests.exceptions.ReadTimeout:
                     self.queue_message(f"  Request timed out reading from {url}", SEVERITY_ERROR)
                except requests.exceptions.ConnectionError as e:
                    self.queue_message(f"  Connection Error: {e}", SEVERITY_ERROR)
                except requests.exceptions.RequestException as e:
                    self.queue_message(f"  Request failed: {e}", SEVERITY_ERROR)
                except Exception as e:
                    self.queue_message(f"  An unexpected error occurred during the request: {e}", SEVERITY_ERROR)

                # Add a small delay
                time.sleep(0.1) # Sleep for 100 milliseconds


            if not cancelled:
                 self.queue_message("--- Directory Traversal Test Completed ---", SEVERITY_HEADER)
                 self.queue_update_status("Directory Traversal Test Completed")
                 self.queue_update_tab_status(test_name, "Completed", "green")

        except Exception as e:
            self.queue_message(f"An unexpected error occurred during the {test_name} test: {e}", SEVERITY_ERROR)
            self.queue_update_status(f"Error during {test_name} test")
            self.queue_update_tab_status(test_name, "Error", "red")
            cancelled = True

        finally:
            self.queue_reset_progress(test_name)
            self.queue_enable_button(self.run_directory_traversal_button)
            if cancelled:
                 self.queue_message(f"--- {test_name.replace('_', ' ').title()} Test Cancelled ---", SEVERITY_HEADER)
                 self.queue_update_tab_status(test_name, "Cancelled", "orange")
                 self.queue_update_status(f"{test_name.replace('_', ' ').title()} Test Cancelled")

            if test_name in self.running_tests:
                del self.running_tests[test_name]
            if not self.running_tests:
                 self.queue_update_status("Ready")


    def run_data_modification_thread(self):
        # --- Input Validation (remains in GUI thread) ---
        api_url = self.dm_api_url_entry.get().strip()
        data_id = self.dm_data_id_entry.get().strip()
        new_value = self.dm_new_value_entry.get().strip()
        method = self.dm_method_type.get().strip()
        request_body_string = self.dm_request_body_text.get("1.0", tk.END).strip()
        custom_headers_string = self.dm_custom_headers_text.get("1.0", tk.END).strip()
        verify_url = self.dm_verify_url_entry.get().strip()
        auth_params = self.get_auth_params_from_gui(TEST_DATA_MODIFICATION)


        normalized_api_url = self.normalize_url(api_url)
        normalized_verify_url = self.normalize_url(verify_url) if verify_url else None

        if not self.validate_url(normalized_api_url):
             messagebox.showerror("Invalid Input", "Please enter a valid API URL (must include http:// or https:// and domain).")
             self.queue_update_status("Invalid API URL")
             self.queue_update_tab_status(TEST_DATA_MODIFICATION, "Validation Error", "red")
             return

        if method in ["POST", "PUT", "PATCH"]:
            if not request_body_string and not new_value and not data_id:
                messagebox.showwarning("Missing Input", f"For {method} method, please provide Request Body, or Data ID, or New Value.")
                self.queue_update_status("Missing DM parameters")
                self.queue_update_tab_status(TEST_DATA_MODIFICATION, "Missing Input", "red")
                return

            if request_body_string:
                try:
                    # Attempt to parse as JSON to give feedback
                    json.loads(request_body_string)
                except json.JSONDecodeError as e:
                    messagebox.showwarning("Input Warning", f"Request Body does not appear to be valid JSON: {e}")
                    # Allow sending non-JSON, but warn the user
                    self.queue_message(f"Warning: Request Body does not appear to be valid JSON: {e}", SEVERITY_WARNING)


        custom_headers = self.parse_headers_string(custom_headers_string)


        # --- Prepare and Start Thread ---
        self.queue_disable_button(self.run_data_modification_button)
        # Progress bar config? This test is typically one request, maybe use indeterminate or remove?
        # Let's keep it determinate with max 2 (modify + verify) if verify URL is provided, otherwise max 1
        max_progress = 2 if normalized_verify_url else 1
        self.dm_progress.config(mode="determinate", maximum=max_progress, value=0)
        self.queue_update_progress(TEST_DATA_MODIFICATION, 0) # Show and reset


        self.queue_message(f"--- Starting {TEST_DATA_MODIFICATION.replace('_', ' ').title()} Test ---", SEVERITY_HEADER)
        self.queue_update_status(f"Running {TEST_DATA_MODIFICATION.replace('_', ' ').title()} Test...")
        self.queue_update_tab_status(TEST_DATA_MODIFICATION, "Running...", "blue")

        thread_name = TEST_DATA_MODIFICATION
        thread = threading.Thread(target=self.perform_data_modification_test, args=(normalized_api_url, data_id, new_value, method, request_body_string, custom_headers, normalized_verify_url, auth_params, thread_name))
        self.running_tests[thread_name] = thread
        thread.start()

    def perform_data_modification_test(self, api_url, data_id, new_value, method, request_body_string, custom_headers, verify_url, auth_params, test_name):
        cancelled = False
        auth_arg, auth_headers = self.get_auth_headers(auth_params)
        combined_headers = {**custom_headers, **auth_headers}

        # Construct the final URL for modification (append data_id if present and not already in URL)
        target_url = api_url
        if data_id and data_id not in api_url:
             target_url = urljoin(api_url, str(data_id)) # urljoin handles trailing/leading slashes

        # Determine request body
        request_body = None
        if request_body_string:
            try:
                # Send as JSON if it parses, otherwise send as plain string/form data depending on headers
                request_body = json.loads(request_body_string)
                # Add Content-Type: application/json header if not already present
                if 'Content-Type' not in combined_headers:
                     combined_headers['Content-Type'] = 'application/json'
            except json.JSONDecodeError:
                request_body = request_body_string # Send as string if not valid JSON
                # Content-Type might need to be set manually by the user if not JSON

        elif new_value:
            # If no request body string but new_value is provided, create a simple body.
            # This assumes a simple key-value or just the value itself.
            # This part might need refinement based on expected API formats.
            # For now, let's assume a simple JSON body if no explicit body is given.
             try:
                 request_body = {"value": new_value} # Example: {"value": "new_data"}
                 if data_id:
                      request_body["id"] = data_id # Example: {"id": "123", "value": "new_data"}
                 if 'Content-Type' not in combined_headers:
                      combined_headers['Content-Type'] = 'application/json'
                 self.queue_message("Constructing JSON body from Data ID and New Value.", SEVERITY_INFO)
             except Exception as e:
                 self.queue_message(f"Error constructing default JSON body: {e}", SEVERITY_ERROR)
                 request_body = new_value # Fallback to sending the raw new_value


        try:
            # --- Perform Modification Request ---
            self.queue_message(f"Performing {method} request to: {target_url}", SEVERITY_INFO)
            if request_body:
                 # Use json=... for JSON bodies, data=... for form-encoded or raw string
                 if isinstance(request_body, dict):
                      self.queue_message(f"  Request Body (JSON): {json.dumps(request_body)}", SEVERITY_INFO)
                      response = self.session.request(method, target_url, headers=combined_headers, auth=auth_arg, json=request_body, timeout=10, proxies=self.get_random_proxy())
                 else:
                      self.queue_message(f"  Request Body (Raw): {request_body}", SEVERITY_INFO)
                      response = self.session.request(method, target_url, headers=combined_headers, auth=auth_arg, data=request_body, timeout=10, proxies=self.get_random_proxy())
            else:
                 response = self.session.request(method, target_url, headers=combined_headers, auth=auth_arg, timeout=10, proxies=self.get_random_proxy())


            status_code = response.status_code
            self.queue_message(f"  Modification Response Status Code: {status_code}", SEVERITY_INFO)

            if status_code in [200, 201, 204]: # Common success codes for modification
                 self.queue_message("  Modification request likely successful (based on status code).", SEVERITY_SUCCESS)
            elif status_code in [401, 403]:
                 self.queue_message("  Modification request failed due to authentication/authorization.", SEVERITY_ERROR)
            elif status_code in [404]:
                 self.queue_message("  Modification target not found (404).", SEVERITY_WARNING)
            else:
                 self.queue_message(f"  Modification request returned status code {status_code}.", SEVERITY_INFO)

            self.queue_update_progress(test_name, 1) # Update progress after modification attempt

            # --- Perform Verification Request (if URL provided) ---
            if verify_url and not self._stop_threads:
                self.queue_message(f"Performing GET request for verification to: {verify_url}", SEVERITY_INFO)
                # Use the same auth/headers for verification
                verify_response = self.session.get(verify_url, headers=combined_headers, auth=auth_arg, timeout=10, proxies=self.get_random_proxy())
                verify_status_code = verify_response.status_code
                self.queue_message(f"  Verification Response Status Code: {verify_status_code}", SEVERITY_INFO)

                if verify_status_code == 200:
                    self.queue_message("  Verification request returned 200 OK. Check response content.", SEVERITY_INFO)
                    # Attempt to print response body if possible and not too large
                    try:
                        self.queue_message(f"  Verification Response Body Sample: {verify_response.text[:500]}...", SEVERITY_INFO) # Print first 500 chars
                    except Exception as e:
                        self.queue_message(f"  Could not display verification response body: {e}", SEVERITY_WARNING)

                elif verify_status_code in [401, 403]:
                     self.queue_message("  Verification failed due to authentication/authorization.", SEVERITY_WARNING)
                elif verify_status_code == 404:
                     self.queue_message("  Verification URL not found (404).", SEVERITY_WARNING)
                else:
                     self.queue_message(f"  Verification request returned status code {verify_status_code}.", SEVERITY_INFO)

                self.queue_update_progress(test_name, 2) # Update progress after verification attempt

            elif self._stop_threads and verify_url:
                 self.queue_message("Verification skipped due to cancellation.", SEVERITY_WARNING)


            if not cancelled:
                 self.queue_message("--- Data Modification Test Completed ---", SEVERITY_HEADER)
                 self.queue_update_status("Data Modification Test Completed")
                 self.queue_update_tab_status(test_name, "Completed", "green")

        except requests.exceptions.ConnectTimeout:
             self.queue_message(f"  Request timed out connecting to {target_url if not verify_url else verify_url}", SEVERITY_ERROR)
        except requests.exceptions.ReadTimeout:
             self.queue_message(f"  Request timed out reading from {target_url if not verify_url else verify_url}", SEVERITY_ERROR)
        except requests.exceptions.ConnectionError as e:
            self.queue_message(f"  Connection Error: {e}", SEVERITY_ERROR)
        except requests.exceptions.RequestException as e:
            self.queue_message(f"  Request failed: {e}", SEVERITY_ERROR)
        except Exception as e:
            self.queue_message(f"An unexpected error occurred during the {test_name} test: {e}", SEVERITY_ERROR)
            self.queue_update_status(f"Error during {test_name} test")
            self.queue_update_tab_status(test_name, "Error", "red")
            cancelled = True

        finally:
            self.queue_reset_progress(test_name)
            self.queue_enable_button(self.run_data_modification_button)
            if cancelled:
                 self.queue_message(f"--- {test_name.replace('_', ' ').title()} Test Cancelled ---", SEVERITY_HEADER)
                 self.queue_update_tab_status(test_name, "Cancelled", "orange")
                 self.queue_update_status(f"{test_name.replace('_', ' ').title()} Test Cancelled")

            if test_name in self.running_tests:
                del self.running_tests[test_name]
            if not self.running_tests:
                 self.queue_update_status("Ready")


    # --- Cancellation and Closing ---

    def cancel_all_tests(self):
        """Signals all running test threads to stop."""
        if not self.running_tests:
            self.queue_update_status("No tests running to cancel.")
            messagebox.showinfo("Cancellation", "No tests are currently running.")
            return

        if messagebox.askyesno("Confirm Cancellation", "Are you sure you want to cancel all running tests?"):
            self._stop_threads = True
            self.queue_update_status("Cancellation requested...")
            self.queue_message("Cancellation requested for all tests.", SEVERITY_WARNING)
            # Threads will check _stop_threads flag and clean up in their finally blocks

    def on_closing(self):
        """Handles the window closing event."""
        if self.running_tests:
            if messagebox.askyesno("Quit", "Tests are still running. Do you want to cancel them and quit?"):
                self._stop_threads = True
                # Wait a bit for threads to acknowledge stop request and finish cleanup
                # In a more complex app, you might want a more sophisticated join/timeout mechanism
                time.sleep(0.5)
                self.master.destroy()
            # else: don't close the window
        else:
            self.master.destroy()

    # --- Settings Save/Load ---

    def collect_settings(self, include_credentials=False):
        """Collects settings from the GUI."""
        settings = {
            "general": {
                "base_url": self.base_url_entry.get().strip(),
                "proxies": self.proxy_text.get("1.0", tk.END).strip()
            },
            TAB_FAILED_LOGINS: {
                "login_url": self.failed_logins_url_entry.get().strip(),
                "attempts": self.failed_logins_attempts_entry.get().strip()
            },
            TAB_DIRECTORY_TRAVERSAL: {
                "target_path": self.dt_target_path_entry.get().strip(),
                "payloads": self.dt_payloads_text.get("1.0", tk.END).strip(),
                "custom_headers": self.dt_custom_headers_text.get("1.0", tk.END).strip(),
                "auth_type": self.dt_auth_type.get()
            },
            TAB_DATA_MODIFICATION: {
                "api_url": self.dm_api_url_entry.get().strip(),
                "data_id": self.dm_data_id_entry.get().strip(),
                "new_value": self.dm_new_value_entry.get().strip(),
                "method": self.dm_method_type.get().strip(),
                "request_body": self.dm_request_body_text.get("1.0", tk.END).strip(),
                "custom_headers": self.dm_custom_headers_text.get("1.0", tk.END).strip(),
                "verify_url": self.dm_verify_url_entry.get().strip(),
                "auth_type": self.dm_auth_type.get()
            }
        }

        if include_credentials:
            # Collect credentials based on selected auth type
            dt_auth = self.get_auth_params_from_gui(TAB_DIRECTORY_TRAVERSAL)
            dm_auth = self.get_auth_params_from_gui(TAB_DATA_MODIFICATION)

            settings[TAB_DIRECTORY_TRAVERSAL]['auth'] = dt_auth
            settings[TAB_DATA_MODIFICATION]['auth'] = dm_auth
            settings[TAB_FAILED_LOGINS]['username'] = self.failed_logins_username_entry.get().strip()
            settings[TAB_FAILED_LOGINS]['password_prefix'] = self.failed_logins_password_prefix_entry.get().strip()


            # Encode sensitive fields (basic obfuscation, NOT secure encryption)
            settings = self._encode_sensitive_fields(settings)


        return settings

    def apply_settings(self, settings):
        """Applies loaded settings to the GUI."""
        general = settings.get("general", {})
        failed_logins = settings.get(TAB_FAILED_LOGINS, {})
        directory_traversal = settings.get(TAB_DIRECTORY_TRAVERSAL, {})
        data_modification = settings.get(TAB_DATA_MODIFICATION, {})

        # Decode sensitive fields if they were encoded
        settings = self._decode_sensitive_fields(settings)
        general = settings.get("general", {}) # Re-get after decoding
        failed_logins = settings.get(TAB_FAILED_LOGINS, {})
        directory_traversal = settings.get(TAB_DIRECTORY_TRAVERSAL, {})
        data_modification = settings.get(TAB_DATA_MODIFICATION, {})


        # General tab
        self.safe_entry_insert(self.base_url_entry, general.get("base_url", ""))
        self.safe_scrolledtext_insert(self.proxy_text, general.get("proxies", ""))

        # Failed Logins tab
        self.safe_entry_insert(self.failed_logins_url_entry, failed_logins.get("login_url", ""))
        self.safe_entry_insert(self.failed_logins_attempts_entry, failed_logins.get("attempts", "10"))
        self.safe_entry_insert(self.failed_logins_username_entry, failed_logins.get("username", ""))
        self.safe_entry_insert(self.failed_logins_password_prefix_entry, failed_logins.get("password_prefix", ""))


        # Directory Traversal tab
        self.safe_entry_insert(self.dt_target_path_entry, directory_traversal.get("target_path", "/"))
        self.safe_scrolledtext_insert(self.dt_payloads_text, directory_traversal.get("payloads", "../\n../../\n...")) # Use default if not loaded
        self.safe_scrolledtext_insert(self.dt_custom_headers_text, directory_traversal.get("custom_headers", ""))

        # Set auth type first to create necessary fields
        dt_auth_type = directory_traversal.get("auth_type", "None")
        self.dt_auth_type.set(dt_auth_type)
        self.set_auth_params_in_gui(TAB_DIRECTORY_TRAVERSAL, directory_traversal.get('auth', {}))


        # Data Modification tab
        self.safe_entry_insert(self.dm_api_url_entry, data_modification.get("api_url", ""))
        self.safe_entry_insert(self.dm_data_id_entry, data_modification.get("data_id", ""))
        self.safe_entry_insert(self.dm_new_value_entry, data_modification.get("new_value", ""))
        self.safe_entry_insert(self.dm_verify_url_entry, data_modification.get("verify_url", ""))
        self.safe_scrolledtext_insert(self.dm_request_body_text, data_modification.get("request_body", ""))
        self.safe_scrolledtext_insert(self.dm_custom_headers_text, data_modification.get("custom_headers", ""))

        # Set auth type first to create necessary fields
        dm_method = data_modification.get("method", "PUT")
        if dm_method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
             self.dm_method_type.set(dm_method)

        dm_auth_type = data_modification.get("auth_type", "None")
        self.dm_auth_type.set(dm_auth_type)
        self.set_auth_params_in_gui(TAB_DATA_MODIFICATION, data_modification.get('auth', {}))


    def _encode_sensitive_fields(self, settings):
        """Encodes sensitive fields using Base64 (basic obfuscation)."""
        encoded_settings = settings.copy() # Work on a copy

        # Failed Logins
        if 'username' in encoded_settings.get(TAB_FAILED_LOGINS, {}):
             encoded_settings[TAB_FAILED_LOGINS]['username'] = base64.b64encode(encoded_settings[TAB_FAILED_LOGINS]['username'].encode()).decode()
        if 'password_prefix' in encoded_settings.get(TAB_FAILED_LOGINS, {}):
             encoded_settings[TAB_FAILED_LOGINS]['password_prefix'] = base64.b64encode(encoded_settings[TAB_FAILED_LOGINS]['password_prefix'].encode()).decode()

        # Directory Traversal Auth
        dt_auth = encoded_settings.get(TAB_DIRECTORY_TRAVERSAL, {}).get('auth', {})
        if dt_auth.get("auth_type") == "Basic Auth":
             if 'username' in dt_auth: dt_auth['username'] = base64.b64encode(dt_auth['username'].encode()).decode()
             if 'password' in dt_auth: dt_auth['password'] = base64.b64encode(dt_auth['password'].encode()).decode()
        elif dt_auth.get("auth_type") == "API Key (Header)":
             if 'header_value' in dt_auth: dt_auth['header_value'] = base64.b64encode(dt_auth['header_value'].encode()).decode()
        elif dt_auth.get("auth_type") == "Bearer Token":
             if 'token' in dt_auth: dt_auth['token'] = base64.b64encode(dt_auth['token'].encode()).decode()
        if dt_auth: encoded_settings[TAB_DIRECTORY_TRAVERSAL]['auth'] = dt_auth # Ensure auth is present even if empty after encoding

        # Data Modification Auth
        dm_auth = encoded_settings.get(TAB_DATA_MODIFICATION, {}).get('auth', {})
        if dm_auth.get("auth_type") == "Basic Auth":
             if 'username' in dm_auth: dm_auth['username'] = base64.b64encode(dm_auth['username'].encode()).decode()
             if 'password' in dm_auth: dm_auth['password'] = base64.b64encode(dm_auth['password'].encode()).decode()
        elif dm_auth.get("auth_type") == "API Key (Header)":
             if 'header_value' in dm_auth: dm_auth['header_value'] = base64.b64encode(dm_auth['header_value'].encode()).decode()
        elif dm_auth.get("auth_type") == "Bearer Token":
             if 'token' in dm_auth: dm_auth['token'] = base64.b64encode(dm_auth['token'].encode()).decode()
        if dm_auth: encoded_settings[TAB_DATA_MODIFICATION]['auth'] = dm_auth # Ensure auth is present even if empty after encoding


        return encoded_settings

    def _decode_sensitive_fields(self, settings):
        """Decodes sensitive fields from Base64."""
        decoded_settings = settings.copy() # Work on a copy

        # Failed Logins
        if 'username' in decoded_settings.get(TAB_FAILED_LOGINS, {}):
             try:
                 decoded_settings[TAB_FAILED_LOGINS]['username'] = base64.b64decode(decoded_settings[TAB_FAILED_LOGINS]['username']).decode()
             except: pass # Ignore decoding errors
        if 'password_prefix' in decoded_settings.get(TAB_FAILED_LOGINS, {}):
             try:
                 decoded_settings[TAB_FAILED_LOGINS]['password_prefix'] = base64.b64decode(decoded_settings[TAB_FAILED_LOGINS]['password_prefix']).decode()
             except: pass # Ignore decoding errors

        # Directory Traversal Auth
        dt_auth = decoded_settings.get(TAB_DIRECTORY_TRAVERSAL, {}).get('auth', {})
        if dt_auth.get("auth_type") == "Basic Auth":
             if 'username' in dt_auth:
                  try: dt_auth['username'] = base64.b64decode(dt_auth['username']).decode()
                  except: pass
             if 'password' in dt_auth:
                 try: dt_auth['password'] = base64.b64decode(dt_auth['password']).decode()
                 except: pass
        elif dt_auth.get("auth_type") == "API Key (Header)":
             if 'header_value' in dt_auth:
                 try: dt_auth['header_value'] = base64.b64decode(dt_auth['header_value']).decode()
                 except: pass
        elif dt_auth.get("auth_type") == "Bearer Token":
             if 'token' in dt_auth:
                 try: dt_auth['token'] = base64.b64decode(dt_auth['token']).decode()
                 except: pass
        if dt_auth: decoded_settings[TAB_DIRECTORY_TRAVERSAL]['auth'] = dt_auth


        # Data Modification Auth
        dm_auth = decoded_settings.get(TAB_DATA_MODIFICATION, {}).get('auth', {})
        if dm_auth.get("auth_type") == "Basic Auth":
             if 'username' in dm_auth:
                  try: dm_auth['username'] = base64.b64decode(dm_auth['username']).decode()
                  except: pass
             if 'password' in dm_auth:
                 try: dm_auth['password'] = base64.b64decode(dm_auth['password']).decode()
                 except: pass
        elif dm_auth.get("auth_type") == "API Key (Header)":
             if 'header_value' in dm_auth:
                 try: dm_auth['header_value'] = base64.b64decode(dm_auth['header_value']).decode()
                 except: pass
        elif dm_auth.get("auth_type") == "Bearer Token":
             if 'token' in dm_auth:
                 try: dm_auth['token'] = base64.b64decode(dm_auth['token']).decode()
                 except: pass
        if dm_auth: decoded_settings[TAB_DATA_MODIFICATION]['auth'] = dm_auth


        return decoded_settings


    def save_settings(self, include_credentials=False):
        """Saves current settings to a JSON file."""
        if include_credentials:
             if not messagebox.askyesno("Warning: Saving Credentials",
                                        "Saving settings with credentials includes sensitive information (passwords, tokens, etc.) "
                                        "in the file. This is NOT recommended for security. Credentials will be lightly obfuscated "
                                        "using Base64, but this is NOT encryption. Are you sure you want to proceed?"):
                 self.queue_update_status("Settings save cancelled.")
                 return


        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Settings"
        )
        if file_path:
            try:
                settings = self.collect_settings(include_credentials)
                with open(file_path, 'w') as f:
                    json.dump(settings, f, indent=4)
                self.queue_message(f"Settings saved to {os.path.basename(file_path)}{' (including credentials)' if include_credentials else ''}", SEVERITY_INFO)
                self.queue_update_status(f"Settings saved to {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save settings: {e}")
                self.queue_message(f"Error saving settings: {e}", SEVERITY_ERROR)
                self.queue_update_status("Error saving settings")

    def load_settings(self, include_credentials=False):
        """Loads settings from a JSON file."""
        if include_credentials:
             messagebox.showwarning("Warning: Loading Credentials",
                                    "Loading settings including credentials will populate sensitive fields "
                                    "(passwords, tokens, etc.) from the selected file. Ensure the file is trusted "
                                    "and handled securely.")

        file_path = filedialog.askopenfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Load Settings"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    settings = json.load(f)

                # Apply settings, decoding happens inside if include_credentials is True
                self.apply_settings(settings)

                self.queue_message(f"Settings loaded from {os.path.basename(file_path)}{' (including credentials)' if include_credentials else ''}", SEVERITY_INFO)
                self.queue_update_status(f"Settings loaded from {os.path.basename(file_path)}")

            except FileNotFoundError:
                messagebox.showerror("Load Error", f"Settings file not found: {file_path}")
                self.queue_message(f"Error loading settings: File not found: {file_path}", SEVERITY_ERROR)
                self.queue_update_status("Error loading settings: File not found")
            except json.JSONDecodeError:
                 messagebox.showerror("Load Error", f"Failed to parse JSON from settings file: {file_path}")
                 self.queue_message(f"Error loading settings: Invalid JSON in file: {file_path}", SEVERITY_ERROR)
                 self.queue_update_status("Error loading settings: Invalid JSON")
            except Exception as e:
                messagebox.showerror("Load Error", f"Failed to load settings: {e}")
                self.queue_message(f"Error loading settings: {e}", SEVERITY_ERROR)
                self.queue_update_status("Error loading settings")


if __name__ == "__main__":
    root = tk.Tk()
    gui = SecurityLoggingTesterGUI(root)
    root.mainloop()
