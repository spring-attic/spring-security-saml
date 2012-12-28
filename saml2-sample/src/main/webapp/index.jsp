<%@ page import="org.springframework.security.saml.SAMLCredential" %>
<%@ page import="org.springframework.security.core.context.SecurityContextHolder" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <title>User authenticated</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body>

<h1>User has been authenticated</h1>

<%
    SAMLCredential credential = (SAMLCredential) SecurityContextHolder.getContext().getAuthentication().getCredentials();
    pageContext.setAttribute("credential", credential);
%>

<p>
<table>
    <tr>
        <td colspan="2"><b>General information</b></td>
    </tr>
    <tr>
        <td width="300">Username:</td>
        <td><c:out value="${credential.nameID.value}"/></td>
    </tr>
    <tr>
        <td>User format:</td>
        <td><c:out value="${credential.nameID.format}"/></td>
    </tr>
    <tr>
        <td>IDP:</td>
        <td><c:out value="${credential.authenticationAssertion.issuer.value}"/></td>
    </tr>
    <tr>
        <td>Assertion issue time:</td>
        <td><c:out value="${credential.authenticationAssertion.issueInstant}"/></td>
    </tr>
</table>
</p>

<p>
<table>
    <tr>
        <td colspan="2"><b>Principal's Attributes</b></td>
    </tr>

    <c:forEach var="attribute"
               items="${credential.attributes}">
        <tr>
            <td width="300"><c:out value="${attribute.friendlyName}"/></td>
            <td>
                <c:forEach var="attributeValue"
                           items="${attribute.attributeValues}">
                    <c:catch var ="catchException">
                        <c:out value="${attributeValue.value}"/>&nbsp;
                    </c:catch>
                    <c:if test="${not empty catchException}">
                        <c:out value="${attributeValue}"/>&nbsp;
                    </c:if>
                </c:forEach>
            </td>
        </tr>
    </c:forEach>
</table>
</p>

<p>
<table>
    <tr>
        <td colspan="2"><b>Subject confirmation</b></td>
    </tr>
    <tr>
        <td width="300">Method:</td>
        <td><c:out value="${credential.authenticationAssertion.subject.subjectConfirmations[0].method}"/></td>
    </tr>
    <tr>
        <td width="300">In response to:</td>
        <td><c:out
                value="${credential.authenticationAssertion.subject.subjectConfirmations[0].subjectConfirmationData.inResponseTo}"/></td>
    </tr>
    <tr>
        <td width="300">Not on or after:</td>
        <td><c:out
                value="${credential.authenticationAssertion.subject.subjectConfirmations[0].subjectConfirmationData.notOnOrAfter}"/></td>
    </tr>
    <tr>
        <td width="300">Recipient:</td>
        <td><c:out
                value="${credential.authenticationAssertion.subject.subjectConfirmations[0].subjectConfirmationData.recipient}"/></td>
    </tr>
</table>
</p>

<p>
<table>
    <tr>
        <td colspan="2"><b>Authentication statement</b></td>
    </tr>
    <tr>
        <td width="300">Authentication instance:</td>
        <td><c:out value="${credential.authenticationAssertion.authnStatements[0].authnInstant}"/></td>
    </tr>
    <tr>
        <td>Session validity:</td>
        <td><c:out value="${credential.authenticationAssertion.authnStatements[0].sessionNotOnOrAfter}"/></td>
    </tr>
    <tr>
        <td>Authentication context class:</td>
        <td><c:out
                value="${credential.authenticationAssertion.authnStatements[0].authnContext.authnContextClassRef.authnContextClassRef}"/></td>
    </tr>
    <tr>
        <td>Session index:</td>
        <td><c:out
                value="${credential.authenticationAssertion.authnStatements[0].sessionIndex}"/></td>
    </tr>
    <tr>
        <td>Subject locality:</td>
        <td><c:out value="${credential.authenticationAssertion.authnStatements[0].subjectLocality.address}"/></td>
    </tr>
</table>
</p>

<p>
<table>
    <tr>
        <td colspan="2"><b>Conditions</b></td>
    </tr>
    <tr>
        <td width="300">Not before:</td>
        <td><c:out value="${credential.authenticationAssertion.conditions.notBefore}"/></td>
    </tr>
    <tr>
        <td width="300">Not on or after:</td>
        <td><c:out value="${credential.authenticationAssertion.conditions.notOnOrAfter}"/></td>
    </tr>
    <tr>
        <td width="300">Audience restriction:</td>
        <td>
            <c:forEach var="audience"
                       items="${credential.authenticationAssertion.conditions.audienceRestrictions[0].audiences}">
                <c:out value="${audience.audienceURI}"/><br/>
            </c:forEach>
        </td>
    </tr>
</table>
</p>

<p>
    <a href="<c:url value="/saml/logout"/>">Global Logout</a><br/>
    <a href="<c:url value="/saml/logout?local=true"/>">Local Logout</a>
</p>

<p>
    <a href="<c:url value="/saml/web/metadata"/>">Metadata information</a>
</p>

</body>
</html>