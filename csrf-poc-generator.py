from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JDialog, JScrollPane, JTextArea, JButton, JPanel, JFileChooser, JCheckBox
from java.awt import BorderLayout, Dimension
from java.net import URLDecoder
import java.awt.Desktop as Desktop
import java.io.File as File
from java.util import ArrayList

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("CSRF PoC Generator")
        callbacks.registerContextMenuFactory(self)
# code 
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
            body = self._helpers.bytesToString(request[body_offset:])  # body string

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

            # Store these to use in popup and update
            self.action_url = action_url
            self.method = method
            self.form_fields = form_fields

            # Generate initial HTML with auto-submit enabled by default
            poc_html = self.build_poc_html(auto_submit=True)

            self.show_popup("Generated CSRF PoC", poc_html)
        except Exception as e:
            print("[ERROR]", e)

    def build_poc_html(self, auto_submit):
        submit_script = ""
        if auto_submit:
            submit_script = """
    <script>
        document.getElementById('csrfForm').submit();
    </script>"""
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

    def show_popup(self, title, content):
        dialog = JDialog()
        dialog.setTitle(title)
        dialog.setSize(850, 650)
        dialog.setModal(True)
        dialog.setLayout(BorderLayout())

        text_area = JTextArea(content)
        text_area.setLineWrap(True)
        text_area.setWrapStyleWord(True)
        text_area.setEditable(False)
        scroll = JScrollPane(text_area)
        scroll.setPreferredSize(Dimension(830, 550))
        dialog.add(scroll, BorderLayout.CENTER)

        button_panel = JPanel()
        save_button = JButton("Save to HTML")
        preview_button = JButton("Preview in Browser")
        close_button = JButton("Close")
        auto_submit_checkbox = JCheckBox("Auto-submit form", True)  # Checked by default

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

        def toggle_auto_submit(event):
            auto_submit = auto_submit_checkbox.isSelected()
            new_html = self.build_poc_html(auto_submit)
            text_area.setText(new_html)

        save_button.addActionListener(save_to_file)
        preview_button.addActionListener(preview_in_browser)
        close_button.addActionListener(close_dialog)
        auto_submit_checkbox.addActionListener(toggle_auto_submit)

        button_panel.add(auto_submit_checkbox)
        button_panel.add(save_button)
        button_panel.add(preview_button)
        button_panel.add(close_button)
        dialog.add(button_panel, BorderLayout.SOUTH)

        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)
