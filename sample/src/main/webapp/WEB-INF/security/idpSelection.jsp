<%@ page import="org.springframework.security.saml.metadata.MetadataManager" %>
<%@ page import="org.springframework.web.context.WebApplicationContext" %>
<%@ page import="org.springframework.web.context.support.WebApplicationContextUtils" %>
<%@ page import="java.util.Set" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <title>Spring Security SAML Extension - Metadata</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body>

<h1>IDP selection</h1>

<%
    WebApplicationContext context = WebApplicationContextUtils.getWebApplicationContext(getServletConfig().getServletContext());
    MetadataManager mm = context.getBean("metadata", MetadataManager.class);
    Set<String> idps = mm.getIDPEntityNames();
    pageContext.setAttribute("idp", idps);
%>

<p>
<form action="<c:url value="${requestScope.idpDiscoReturnURL}"/>" method="GET">
    <table>
        <tr>
            <td><b>Select IDP: </b></td>
            <td>
                <c:forEach var="idpItem" items="${idp}">
                    <input type="radio" name="${requestScope.idpDiscoReturnParam}" id="idp_<c:out value="${idpItem}"/>" value="<c:out value="${idpItem}"/>"/>
                    <label for="idp_<c:out value="${idpItem}"/>"><c:out value="${idpItem}"/></label>
                    <br/>
                </c:forEach>
            </td>
        </tr>
        <tr>
            <td>&nbsp;</td>
            <td><input type="submit" value="Login"/></td>
        </tr>
    </table>
</form>
</p>

<p>
    <a href="<c:url value="/saml/web/metadata"/>">Metadata information</a>
</p>

</body>
</html>