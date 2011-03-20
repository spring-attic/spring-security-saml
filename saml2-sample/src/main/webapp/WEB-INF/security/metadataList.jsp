<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<html>
<head>Spring Security SAML Extension - Metadata</head>
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