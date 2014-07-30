<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" dir="ltr">
<jsp:include page="/WEB-INF/templates/head.jsp" />
<body>
<div id="site-wrapper">
    <jsp:include page="/WEB-INF/templates/navigation.jsp" />
    <div class="main" id="main-two-columns">
        <div class="left" id="main-content">
            <div class="section">
                <div class="section-content">
                    <div class="post">
                        <div class="post-title"><h2 class="label label-green">Login to administration</h2></div>
                        <p class="quiet large">Please login to the metadata administration using a local account (by default admin/admin).</p>
                        <div class="post-body">
                            <% String errorString = (String) request.getAttribute("error"); %>
                            <% if (errorString != null && errorString.trim().equals("true")) { %>
                                <div class="error">Incorrect login name or password. Please retry using correct login name and password.</div>
                            <% } %>
                            <p>
                            <form name='loginForm' action="<c:url value='/saml/web/login' />" method='POST'>
                                <table>
                                    <tr>
                                        <td><label for="username">User:</label></td>
                                        <td><input type='text' name='j_username' id="username" class="text" value='admin'></td>
                                    </tr>
                                    <tr>
                                        <td><label for="password">Password:</label></td>
                                        <td><input type='password' name='j_password' id="password" class="text" value="admin"/></td>
                                    </tr>
                                    <tr>
                                        <td></td>
                                        <td><input name="submit" class="button" type="submit" value="Login"/></td>
                                    </tr>
                                </table>
                            </form>
                        </div>
                    </div>
                    <div class="clearer">&nbsp;</div>
                </div>
            </div>
            <div class="clearer">&nbsp;</div>
        </div>
        <jsp:include page="/WEB-INF/templates/sidebar.jsp" />
    </div>
    <jsp:include page="/WEB-INF/templates/footer.jsp" />
</div>
</body>
</html>