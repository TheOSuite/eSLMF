# eSLMF - Security Logging and Monitoring Failures Tester

**(A GUI Tool for Testing Web Application Security Logging)**

---

## What is eSLMF?

**eSLMF** (Enhanced Security Logging and Monitoring Failures Tester) is a simple, graphical tool designed to help you check if your website or web application is properly **recording important security events**.

Think of it like a "log tester." You use eSLMF to perform actions that *should* be logged (like trying bad passwords or attempting to access restricted areas), and then you check your server's logs to see if they were actually recorded correctly.

**Why is this important?** Proper logging is crucial for:
* Detecting potential attacks or suspicious activity.
* Troubleshooting problems.
* Understanding how users (and attackers) interact with your application.
* Meeting security compliance requirements.

eSLMF simulates common events like:
* **Failed Login Attempts:** Trying incorrect passwords multiple times.
* **Directory Traversal:** Trying to access files or folders outside the allowed web directory.
* **Data Modification:** Sending requests to change or delete data via an API.

**Important:** eSLMF is **not** a hacking tool. It's designed to *generate noise* that your logging system *should* pick up. The real work happens when you **check your application's logs** after running a test.

**Source Code:** [https://github.com/fish-hue/eSLMF](https://github.com/fish-hue/eSLMF)

---

## Why Use eSLMF?

* **Easy to Use:** Simple graphical interface – no complex commands needed to run basic tests.
* **Verification:** Helps you confirm your logging is working as expected *before* a real incident happens.
* **Beginner Friendly:** A good starting point for understanding and testing basic security logging concepts.
* **Visual Feedback:** See requests being sent and basic status updates directly in the tool.

---

## Features Explained

* **Graphical User Interface (GUI):** A visual window with buttons and fields, making it easier to use than command-line tools.
* **Tabbed Interface:** Tests are organized logically:
    * **General:** Basic setup (target website, optional proxies).
    * **Failed Logins:** Test if brute-force login attempts are logged.
    * **Directory Traversal:** Test if attempts to access restricted files/folders are logged.
    * **Data Modification:** Test if API calls (PUT, POST, etc.) that change data are logged.
* **Proxy Support:**
    * *Why?* Test how your application logs requests coming from different potential sources or IP addresses.
    * Allows manual entry, loading/saving from a file.
* **Authentication Options:**
    * *Why?* Test logging for parts of your application protected by different login methods (Basic Auth, API Keys, Tokens).
* **Custom Headers:**
    * *Why?* Some attacks or tests require specific HTTP headers; this lets you add them.
* **Asynchronous Testing:** Tests run in the background so the GUI doesn't freeze.
* **Real-time Output Log:** Shows what the tool is doing, including status codes from the server (like `200 OK`, `404 Not Found`, `403 Forbidden`). Color-coded for readability.
* **Status Updates:** Quick status messages in the window's status bar and on each test tab.
* **Progress Bars:** A visual indicator for tests that send multiple requests.
* **Save/Load Configuration:** Save your test setups to a file so you don't have to re-enter everything. **(See Security Warning about saving credentials!)**
* **Cancel Operation:** Stop running tests if needed.

---

## Getting Started (Installation & Setup)

You'll need Python and Git installed on your computer.

**1. Install Python:**
* eSLMF is written in Python. You need Python 3.x installed.
* Check if you have it: Open your terminal or command prompt and type `python --version` or `python3 --version`.
* If you don't have it, download it from the official Python website: [https://www.python.org/downloads/](https://www.python.org/downloads/)

**2. Install Git (Optional, but recommended):**
* Git is a tool used to download code from repositories like GitHub.
* Check if you have it: Open your terminal and type `git --version`.
* If you don't have it, download it from: [https://git-scm.com/downloads](https://git-scm.com/downloads)

**3. Download eSLMF:**

* **Option A (Using Git - Recommended):**
    * Open your terminal or command prompt.
    * Navigate to the directory where you want to save the tool.
    * Clone the repository using this command:
        ```bash
        git clone [https://github.com/fish-hue/eSLMF.git](https://github.com/fish-hue/eSLMF.git)
        ```
    * This will create an `eSLMF` folder with the code.

* **Option B (Download ZIP):**
    * Go to the GitHub page: [https://github.com/fish-hue/eSLMF](https://github.com/fish-hue/eSLMF)
    * Click the green "<> Code" button.
    * Click "Download ZIP".
    * Unzip the downloaded file. You'll have an `eSLMF-main` (or similar) folder.

**4. Install Required Library:**
* eSLMF uses the `requests` library to send HTTP requests (like visiting a webpage).
* Open your terminal or command prompt.
* **Navigate into the eSLMF directory** you created/unzipped:
    ```bash
    cd eSLMF
    # or cd eSLMF-main if you downloaded the ZIP
    ```
* Install the library using `pip`, Python's package installer:
    ```bash
    pip install requests
    # or use pip3 install requests if pip doesn't work
    ```

---

## Running eSLMF

1.  Make sure you are in the `eSLMF` directory in your terminal (use the `cd` command to navigate).
2.  Run the script using Python:
    ```bash
    python eSLMF.py
    # or use python3 eSLMF.py if python doesn't work
    ```
3.  The eSLMF graphical window should appear!

---

## How to Use the Tabs (Basic Walkthrough)

**Remember: The goal is to run a test and then check your *server logs* to see if the actions were recorded.**

1.  **General Tab:**
    * **Base URL:** Enter the main starting address of the website or application you are testing (e.g., `https://your-test-site.com`).
    * **Proxies (Optional):** If you need requests to go through a proxy server, enter the proxy addresses here (one per line, e.g., `http://127.0.0.1:8080`). You can also load/save these.

2.  **Failed Logins Tab:**
    * **Goal:** Check if multiple wrong password attempts are logged.
    * **Login URL:** The *exact* address of the login page/API endpoint.
    * **Username:** The username you're testing with.
    * **Password Prefix:** The tool will create bad passwords like `prefix1`, `prefix2`, etc. Enter the `prefix` part here.
    * **Number of Attempts:** How many bad passwords to try.
    * Click **Run Failed Logins Test**.
    * **After:** Check your server logs for login failure events related to the username.

3.  **Directory Traversal Tab:**
    * **Goal:** Check if attempts to access files outside the web root (like `../../etc/passwd`) are logged.
    * **Target Path:** The part of the URL *after* the Base URL where the bad path will be added, often a parameter (e.g., `/app/getFile?filename=`).
    * **Traversal Payloads:** The "bad paths" to try (like `../`, `../../`, `%2e%2e%2f`). Add one per line or load from a file.
    * **Authentication (Optional):** If the target path requires login, select the method and enter credentials.
    * Click **Run Directory Traversal Test**.
    * **After:** Check server logs for errors or access attempts related to the payloads sent.

4.  **Data Modification Tab:**
    * **Goal:** Check if API requests that modify data (like updating user profiles or deleting posts) are logged.
    * **API URL:** The full URL of the API endpoint you are testing.
    * **HTTP Method:** Choose the type of request (POST, PUT, PATCH, DELETE).
    * **Request Body (Optional):** For methods like POST/PUT, enter the data to send (e.g., JSON).
    * **Authentication (Optional):** Provide login details if the API requires them.
    * Click **Run Data Modification Test**.
    * **After:** Check server logs for records of the API call being made, including who made it (if authenticated) and what was changed.

---

## Understanding the Output & Controls

* **Output Area:** The large text box shows a log of what eSLMF is doing: sending requests, receiving responses (like status codes), and any errors.
* **Status Bar:** The bar at the bottom shows the overall status ("Ready", "Running...", "Error").
* **Tab Status:** Each test tab shows its current status ("Ready", "Running...", "Finished", "Cancelled", "Error").
* **Save/Load Settings:** Use these buttons at the bottom to save your configurations for later use. **Be careful if saving credentials!**
* **Cancel All Tests:** Stops any tests currently running.

---

## Important Considerations

**⚠️ Security Warning - Saving Credentials ⚠️**

* This tool lets you save test configurations, **optionally including credentials** (passwords, API keys, tokens).
* **USE THIS FEATURE WITH EXTREME CAUTION.**
* Credentials are saved using Base64 encoding, which is **NOT secure encryption**. It's easily reversible.
* **DO NOT** save sensitive production credentials this way.
* Avoid storing configuration files containing credentials insecurely.
* Prefer the "Save Settings (No Credentials)" option.

**⚖️ Disclaimer ⚖️**

* This tool is for **authorized security testing only**.
* **Only use eSLMF on systems you have explicit permission to test.**
* Unauthorized use may be illegal and unethical.
* The author is not responsible for any misuse or damage caused by this tool.

---

## Reporting Issues & Suggestions

If you find a bug or have an idea for improving eSLMF, please open an issue on the GitHub repository:
[https://github.com/fish-hue/eSLMF/issues](https://github.com/fish-hue/eSLMF/issues)

---

## License

This project is licensed under the MIT License. See the `LICENSE` file in the repository for details.
