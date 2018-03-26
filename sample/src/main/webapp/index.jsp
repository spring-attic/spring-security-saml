<%@ page import="org.springframework.security.saml.SAMLCredential" %>
<%@ page import="org.springframework.security.core.context.SecurityContextHolder" %>
<%@ page import="org.springframework.security.core.Authentication" %>
<%@ page import="org.opensaml.saml2.core.Attribute" %>
<%@ page import="org.springframework.security.saml.util.SAMLUtil" %>
<%@ page import="org.opensaml.xml.util.XMLHelper" %>
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
                        <div class="post-title"><h2 class="label label-green">Authenticated user</h2></div>
                        <p class="quiet large">Overview of the authenticated user's data.</p>
                        <div class="post-body">
                            <%
                                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                                SAMLCredential credential = (SAMLCredential) authentication.getCredentials();
                                pageContext.setAttribute("authentication", authentication);
                                pageContext.setAttribute("credential", credential);
                                pageContext.setAttribute("assertion", XMLHelper.nodeToString(SAMLUtil.marshallMessage(credential.getAuthenticationAssertion())));
                            %>
                            <p>
                            <table>
                                <tr>
                                    <td colspan="2"><h5>General information</h5></td>
                                </tr>
                                <tr>
                                    <td width="200"><strong>Name:</strong></td>
                                    <td><c:out value="${authentication.name}"/></td>
                                </tr>
                                <tr>
                                    <td><strong>Principal:</strong></td>
                                    <td><c:out value="${authentication.principal}"/></td>
                                </tr>
                                <tr>
                                    <td><strong>Name ID:</strong></td>
                                    <td><c:out value="${credential.nameID.value}"/></td>
                                </tr>
                                <tr>
                                    <td><strong>Name ID format:</strong></td>
                                    <td><c:out value="${credential.nameID.format}"/></td>
                                </tr>
                                <tr>
                                    <td><strong>IDP:</strong></td>
                                    <td><c:out value="${credential.authenticationAssertion.issuer.value}"/></td>
                                </tr>
                                <tr>
                                    <td><strong>Assertion issue time:</strong></td>
                                    <td><c:out value="${credential.authenticationAssertion.issueInstant}"/></td>
                                </tr>
                            </table>
                            <p>
                            <table>
                                <tr>
                                    <td colspan="2"><h5>Principal's SAML attributes</h5></td>
                                </tr>
                                <c:forEach var="attribute" items="${credential.attributes}">
                                    <tr>
                                        <td width="200">
                                            <strong><c:out value="${attribute.name}"/></strong><c:if test="${not empty attribute.friendlyName}"> (<c:out value="${attribute.friendlyName}"/>)</c:if>
                                        </td>
                                        <td>
                                            <%
                                                Attribute a = (Attribute) pageContext.getAttribute("attribute");
                                                String[] attributeValues = credential.getAttributeAsStringArray(a.getName());
                                                pageContext.setAttribute("attributeValues", attributeValues);
                                            %>
                                            <c:forEach var="attributeValue" items="${attributeValues}">
                                                <c:out value="${attributeValue}"/>&nbsp;
                                            </c:forEach>
                                        </td>
                                    </tr>
                                </c:forEach>
                            </table>
                            <p>
                            <table>
                                <tr>
                                    <td colspan="2"><h5>Subject confirmation</h5></td>
                                </tr>
                                <tr>
                                    <td width="200"><strong>Method:</strong></td>
                                    <td><c:out
                                            value="${credential.authenticationAssertion.subject.subjectConfirmations[0].method}"/></td>
                                </tr>
                                <tr>
                                    <td><strong>In response to:</strong></td>
                                    <td><c:out
                                            value="${credential.authenticationAssertion.subject.subjectConfirmations[0].subjectConfirmationData.inResponseTo}"/></td>
                                </tr>
                                <tr>
                                    <td><strong>Not on or after:</strong></td>
                                    <td><c:out
                                            value="${credential.authenticationAssertion.subject.subjectConfirmations[0].subjectConfirmationData.notOnOrAfter}"/></td>
                                </tr>
                                <tr>
                                    <td><strong>Recipient:</strong></td>
                                    <td><c:out
                                            value="${credential.authenticationAssertion.subject.subjectConfirmations[0].subjectConfirmationData.recipient}"/></td>
                                </tr>
                            </table>
                            <p>
                            <table>
                                <tr>
                                    <td colspan="2"><h5>Authentication statement</h5></td>
                                </tr>
                                <tr>
                                    <td width="200"><strong>Authentication instance:</strong></td>
                                    <td><c:out
                                            value="${credential.authenticationAssertion.authnStatements[0].authnInstant}"/></td>
                                </tr>
                                <tr>
                                    <td><strong>Session validity:</strong></td>
                                    <td><c:out
                                            value="${credential.authenticationAssertion.authnStatements[0].sessionNotOnOrAfter}"/></td>
                                </tr>
                                <tr>
                                    <td><strong>Authentication context class:</strong></td>
                                    <td><c:out
                                            value="${credential.authenticationAssertion.authnStatements[0].authnContext.authnContextClassRef.authnContextClassRef}"/></td>
                                </tr>
                                <tr>
                                    <td><strong>Session index:</strong></td>
                                    <td><c:out
                                            value="${credential.authenticationAssertion.authnStatements[0].sessionIndex}"/></td>
                                </tr>
                                <tr>
                                    <td><strong>Subject locality:</strong></td>
                                    <td><c:out
                                            value="${credential.authenticationAssertion.authnStatements[0].subjectLocality.address}"/></td>
                                </tr>
                            </table>
                            <p>
                            <table>
                                <tr>
                                    <td colspan="2"><h5>Conditions</h5></td>
                                </tr>
                                <tr>
                                    <td width="200"><strong>Not before:</strong></td>
                                    <td><c:out value="${credential.authenticationAssertion.conditions.notBefore}"/></td>
                                </tr>
                                <tr>
                                    <td><strong>Not on or after:</strong></td>
                                    <td><c:out
                                            value="${credential.authenticationAssertion.conditions.notOnOrAfter}"/></td>
                                </tr>
                                <tr>
                                    <td><strong>Audience restriction:</strong></td>
                                    <td>
                                        <c:forEach var="audience"
                                                   items="${credential.authenticationAssertion.conditions.audienceRestrictions[0].audiences}">
                                            <c:out value="${audience.audienceURI}"/><br/>
                                        </c:forEach>
                                    </td>
                                </tr>
                            </table>
                            <p>
                            <table>
                                <tr>
                                    <td><h5>Assertion XML</h5></td>
                                </tr>
                                <tr>
                                    <td>
                                        <textarea style="height: 400px" disabled="disabled"><c:out value="${assertion}"/></textarea>
                                    </td>
                                </tr>
                            </table>
                            <div>
                                <form class="left" action="<c:url value="/saml/logout"/>" method="get">
                                    <input type="submit" value="Global Logout" class="button"/>
                                </form>
                                <form class="left" action="<c:url value="/saml/logout"/>" method="get">
                                    <input type="hidden" name="local" value="true"/>
                                    <input type="submit" value="Local Logout" class="button"/>
                                </form>
                            </div>
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