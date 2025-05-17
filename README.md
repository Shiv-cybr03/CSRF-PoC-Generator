# CSRF PoC Generator - Burp Suite Extension

A Burp Suite extension that generates CSRF (Cross-Site Request Forgery) Proof-of-Concept (PoC) HTML forms from selected HTTP requests.  
It allows security testers to quickly create CSRF attack payloads with options to auto-submit, save to file, and preview in a browser.

---

## Features

- Generates CSRF PoC HTML forms from HTTP **GET** and **POST** requests.
- Automatically extracts parameters from URL query string (GET) or request body (POST).
- Supports auto-submitting the CSRF form on page load or manual submission.
- Popup window interface for viewing, saving, and previewing the generated PoC.
- Save generated PoC to an HTML file.
- Preview the CSRF PoC in the default system browser directly from Burp.
- Easy integration as a context menu item inside Burp Suite.

---

## Requirements

- Burp Suite Professional or Community Edition (latest recommended).
- Jython standalone JAR (version 2.7.x) for Python extension support.

---

## Installation

1. Download the Jython standalone JAR from [https://www.jython.org/downloads.html](https://www.jython.org/downloads.html).  
   Example: `jython-standalone-2.7.2.jar`

2. Save the extension script `csrf_poc_generator.py` to your local machine.

3. Open Burp Suite.

4. Navigate to the **Extender** tab.

5. Click on the **Extensions** sub-tab.

6. Click **Add**.

7. In the "Add Extension" window:  
   - Select **Extension type:** `Python`.  
   - For **Extension file:** browse and select the `csrf_poc_generator.py` file.  
   - For **Python Environment:** browse and select the downloaded `jython-standalone-2.7.x.jar`.

8. Click **Next** or **Load** to load the extension.

9. You should now see **CSRF PoC Generator** in the list of loaded extensions.

---

## Usage

1. In Burp Suite, go to any tool where HTTP requests are displayed (e.g., **Proxy** > HTTP history, **Repeater**, or **Intruder**).

2. Right-click on a request you want to generate a CSRF PoC for.

3. In the context menu, click **Generate CSRF PoC**.

4. A popup window will appear showing the generated CSRF PoC HTML form.

5. Popup controls:  
   - **Auto-submit form** (checkbox): Enable or disable automatic form submission on page load.  
   - **Save to HTML**: Save the current PoC HTML to a file for later use or sharing.  
   - **Preview in Browser**: Opens the generated PoC in your default browser to test the attack.  
   - **Close**: Close the popup window.

---

## How It Works

- For **POST** requests, the extension parses form parameters from the request body and creates hidden input fields with their values.
- For **GET** requests, it parses query string parameters and creates corresponding hidden inputs.
- It builds an HTML form targeting the original request URL with the correct HTTP method (GET or POST).
- If auto-submit is enabled, the form will submit immediately when loaded in a browser.

---

## Example

Suppose you have a POST request with the following parameters:

