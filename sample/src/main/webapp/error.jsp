<%@ page import="java.io.StringWriter" %>
<%@ page import="java.io.PrintWriter" %>
<%@ page import="org.springframework.security.web.WebAttributes" %>
<%@ page isErrorPage="true" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" dir="ltr">
<jsp:include page="/WEB-INF/templates/head.jsp"/>
<body>
<div id="site-wrapper">
    <jsp:include page="/WEB-INF/templates/navigation.jsp"/>
    <div class="main" id="main-two-columns">
        <div class="left" id="main-content">
            <div class="section">
                <div class="section-content">
                    <div class="post">
                        <div class="post-title"><h2 class="label label-green">Error</h2></div>
                        <p class="quiet large">An error occurred.</p>
                        <div class="post-body">
                            <%
                                // Load exception set from Spring Security unless set from web.xml error handler
                                if (exception == null) {
                                    exception = (Throwable) request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
                                }
                            %>
                            <% if (exception != null) { %>
                                <strong>Message:</strong><br>
                                <%= exception.getMessage() %>
                                <br><br>
                                <strong>StackTrace:</strong><br>
                                <div style="width: 100%; overflow: scroll"><pre><%
                                    StringWriter stringWriter = new StringWriter();
                                    PrintWriter printWriter = new PrintWriter(stringWriter);
                                    exception.printStackTrace(printWriter);
                                    out.println(stringWriter);
                                    printWriter.close();
                                    stringWriter.close();
                                %></pre></div>
                                <br>
                                <strong>Make sure to hide error content from your production environments to minimize leakage of useful data to potential
                                attackers.</strong>
                            <% } %>
                        </div>
                    </div>
                    <div class="clearer">&nbsp;</div>
                </div>
            </div>
            <div class="clearer">&nbsp;</div>
        </div>
        <jsp:include page="/WEB-INF/templates/sidebar.jsp"/>
    </div>
    <jsp:include page="/WEB-INF/templates/footer.jsp"/>
</div>
</body>
</html>