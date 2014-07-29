<%@ page import="java.io.StringWriter" %>
<%@ page import="java.io.PrintWriter" %>
<%@ page import="org.springframework.security.web.WebAttributes" %>
<%@ page isErrorPage="true" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <title>Error</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body>
<h1>An error occurred</h1>

<%
    // Load exception set from Spring Security unless set from web.xml error handler
    if (exception == null) {
        exception = (Throwable) request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }
%>

<% if (exception != null) { %>

    <strong>Message:</strong><br>
    <%= exception.getMessage() %>

    <p>
    <strong>StackTrace:</strong><br>
    <pre>
    <%
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        exception.printStackTrace(printWriter);
        out.println(stringWriter);
        printWriter.close();
        stringWriter.close();
    %>
    </pre>

    <p>
    <strong>Make sure to hide error content from your production environments to minimize leakage of useful data to potential
    attackers.</strong>

<% } %>

</body>