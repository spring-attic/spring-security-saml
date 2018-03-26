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
                                        <td><strong>Local entity:</strong></td>
                                        <td><c:out value="${metadata.local}"/></td>
                                    </tr>
                                    <tr>
                                        <td><strong>Entity ID:</strong></td>
                                        <td><c:out value="${metadata.entityId}"/></td>
                                    </tr>
                                    <c:if test="${metadata.local eq true}">
                                    <tr>
                                        <td><strong>Entity alias:</strong></td>
                                        <td><c:out value="${metadata.alias}"/></td>
                                    </tr>
                                    <tr>
                                        <td><strong>Signing key:</strong></td>
                                        <td><c:out value="${metadata.signingKey}"/></td>
                                    </tr>
                                    <tr>
                                        <td><strong>Encryption key:</strong></td>
                                        <td><c:out value="${metadata.encryptionKey}"/></td>
                                    </tr>
                                    </c:if>
                                    <tr>
                                        <td colspan="2">
                                            <label for="metadata">Metadata:</label><br>
                                            <textarea id="metadata" readonly="readonly"><c:out value="${metadata.serializedMetadata}"/></textarea>
                                        </td>
                                    </tr>
                                    <c:if test="${metadata.local eq true}">
                                        <tr>
                                            <td colspan="2">
                                                <label for="configuration">Configuration:</label><br>
                                                <textarea id="configuration" readonly="readonly"><c:out
                                                        value="${metadata.configuration}"/></textarea>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td colspan="2">
                                                <strong>In order to permanently store the metadata follow these instructions:</strong>
                                                <ul>
                                                    <li>Store metadata content inside your achive at /WEB-INF/classes/metadata/${storagePath}</li>
                                                    <li>Make sure to update your identity provider(s) with the generated metadata</li>
                                                    <li>Modify bean "metadata" in your securityContext.xml and include content from the configuration above</li>
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