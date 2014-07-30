<%@ page import="org.springframework.security.saml.web.MetadataController" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
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
                        <div class="post-title"><h2 class="label label-green">Metadata detail</h2></div>
                        <p class="quiet large">Detail of a single entity imported to Spring SAML's MetadataManager.</p>
                        <div class="post-body">
                            <p><a href="<c:url value="/saml/web/metadata"/>">&lt;&lt Back</a></p>
                            <form:form commandName="metadata">
                                <table>
                                    <tr>
                                        <td><label for="local">Local entity:</label></td>
                                        <td><form:input id="local" readonly="true" path="local"/></td>
                                    </tr>
                                    <tr>
                                        <td><label for="entityId">Entity ID:</label></td>
                                        <td><form:input id="entityId" readonly="true" path="entityId"/></td>
                                    </tr>
                                    <c:if test="${metadata.local eq true}">
                                    <tr>
                                        <td><label for="alias">Entity alias:</label></td>
                                        <td><form:input id="alias" readonly="true" path="alias"/></td>
                                    </tr>
                                    <tr>
                                        <td><label for="signingKey">Signing key:</label></td>
                                        <td><form:input id="signingKey" readonly="true" path="signingKey"/></td>
                                    </tr>
                                    <tr>
                                        <td><label for="encryptionKey">Encryption key:</label></td>
                                        <td><form:input id="encryptionKey" readonly="true" path="encryptionKey"/></td>
                                    </tr>
                                    </c:if>
                                    <tr>
                                        <td colspan="2">
                                            <label for="metadata">Metadata:</label><br>
                                            <textarea rows="15" cols="115" id="metadata" readonly="true"><c:out value="${metadata.serializedMetadata}"/></textarea>
                                        </td>
                                    </tr>
                                    <c:if test="${metadata.local eq true}">
                                        <tr>
                                            <td colspan="2">
                                                <label for="configuration">Configuration:</label><br>
                                                <textarea rows="15" cols="115" id="configuration" readonly="true"><c:out
                                                        value="${metadata.configuration}"/></textarea>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td colspan="2">
                                                <strong>In order to permanently store the metadata follow these instructions:</strong>
                                                <ul>
                                                    <li>Store metadata content in file WEB-INF/classes/security/${storagePath}</li>
                                                    <li>Make sure to update your identity provider(s) with the generated metadata</li>
                                                    <li>Modify bean "metadata" in your securityContext.xml and include content from the configuration bellow</li>
                                                </ul>
                                            </td>
                                        </tr>
                                    </c:if>
                                </table>
                            </form:form>
                            <c:choose>
                            <c:when test="${metadata.alias != null}">
                                <form action="<c:url value="/saml/metadata/alias/${metadata.alias}"/>" method="get">
                                    <input type="submit" value="Download entity metadata" class="button"/>
                                </form>
                            </c:when>
                            <c:otherwise>
                                <form action="<c:url value="/saml/metadata"/>" method="get">
                                    <input type="submit" value="Download entity metadata" class="button"/>
                                </form>
                            </c:otherwise>
                            </c:choose>
                            <br>
                            <p><a href="<c:url value="/saml/web/metadata"/>">&lt;&lt Back</a></p>
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