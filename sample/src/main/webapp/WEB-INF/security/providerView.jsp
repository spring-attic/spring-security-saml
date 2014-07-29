<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <title>Spring Security SAML Extension - Metadata</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body>

<h1>Metadata provider detail</h1>

<p>
    <a href="<c:url value="/saml/web/metadata"/>">&lt;&lt Back</a>
</p>

<form:form commandName="provider" action="removeProvider">

    <input type="hidden" name="providerIndex" value="<c:out value="${providerIndex}"/>"/>

    <table>

        <tr>
            <td>Provider:</td>
            <td><c:out value="${provider}"/></td>
        </tr>

        <tr>
            <td colspan="2">
                <br/>
                <input type="submit" value="Remove provider"/>
            </td>
        </tr>

    </table>

    <p>
        <a href="<c:url value="/saml/web/metadata"/>">&lt;&lt Back</a>
    </p>

</form:form>

</body>
</html>