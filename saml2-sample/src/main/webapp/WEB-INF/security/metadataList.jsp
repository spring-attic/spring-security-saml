<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <title>Spring Security SAML Extension - Metadata</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body>

<h1>Metadata</h1>

<a href="<c:url value="/saml/web/metadata/generate"/>">
    Generate new service provider metadata
</a>

<p>
    Default hosted service provider: <br/>
    <c:forEach var="entity" items="${hostedSP}">
        <a href="<c:url value="/saml/web/metadata/display"><c:param name="entityId" value="${hostedSP}"/></c:url>">
            <c:out value="${hostedSP}"/></a>
    </c:forEach>
    <c:if test="${empty spList}"> - </c:if>
    <br/>
    <small><i>Default service provider is available without selection of alias.</i></small>
</p>

<p>
    Service providers:<br/>
    <c:forEach var="entity" items="${spList}">
        <a href="<c:url value="/saml/web/metadata/display"><c:param name="entityId" value="${entity}"/></c:url>">
            <c:out value="${entity}"/></a><br/>
    </c:forEach>
    <c:if test="${empty spList}"> - </c:if>
</p>

<p>
    Identity providers:<br/>
    <c:forEach var="entity" items="${idpList}">
        <a href="<c:url value="/saml/web/metadata/display"><c:param name="entityId" value="${entity}"/></c:url>">
            <c:out value="${entity}"/></a><br/>
    </c:forEach>
    <c:if test="${empty idpList}"> - </c:if>
</p>

</body>
</html>