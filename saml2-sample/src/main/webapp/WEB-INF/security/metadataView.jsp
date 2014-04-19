<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <title>Spring Security SAML Extension - Metadata</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body>

<h1>Metadata detail</h1>

<p>
    <a href="<c:url value="/saml/web/metadata"/>">&lt;&lt Back</a>
</p>

<form:form commandName="metadata">

    <p>
        <c:choose>
            <c:when test="${metadata.alias != null}">
                <a href="<c:url value="/saml/metadata/alias/${metadata.alias}"/>">Download entity metadata</a>
            </c:when>
            <c:otherwise>
                <a href="<c:url value="/saml/metadata"/>">Download entity metadata</a>
            </c:otherwise>
        </c:choose>
    </p>

    <table>
        <tr>
            <td>Entity ID:</td>
            <td><form:input readonly="true" path="entityId"/></td>
        </tr>
        <tr>
            <td>Entity alias:</td>
            <td><form:input readonly="true" path="alias"/></td>
        </tr>

        <tr>
            <td>Security profile:</td>
            <td>
                <form:select path="securityProfile" multiple="false" disabled="true">
                    <form:option value="metaiop">MetaIOP</form:option>
                    <form:option value="pkix">PKIX</form:option>
                </form:select>
            </td>
        </tr>
        <tr>
            <td>SSL Security profile:</td>
            <td>
                <form:select path="sslSecurityProfile" multiple="false" disabled="true">
                    <form:option value="pkix">PKIX</form:option>
                    <form:option value="metaiop">MetaIOP</form:option>
                </form:select>
            </td>
        </tr>

        <tr>
            <td>Signing key:</td>
            <td><form:input readonly="true" path="signingKey"/></td>
        </tr>
        <tr>
            <td>Encryption key:</td>
            <td><form:input readonly="true" path="encryptionKey"/></td>
        </tr>
        <tr>
            <td>SSL/TLS key:</td>
            <td><form:input readonly="true" path="tlsKey"/></td>
        </tr>

        <tr>
            <td>SSL/TLS Hostname Verification:</td>
            <td>
                <form:select path="sslHostnameVerification" multiple="false" disabled="true">
                    <form:option value="default">Standard hostname verifier</form:option>
                    <form:option value="defaultAndLocalhost">Standard hostname verifier (skips verification for localhost)</form:option>
                    <form:option value="strict">Strict hostname verifier</form:option>
                    <form:option value="allowAll">Disable hostname verification (allow all)</form:option>
                </form:select>
            </td>
        </tr>

        <tr>
            <td>Require signed LogoutRequest:</td>
            <td>
                <form:select path="requireLogoutRequestSigned" multiple="false" disabled="true">
                    <form:option value="true">Yes</form:option>
                    <form:option value="false">No</form:option>
                </form:select>
            </td>
        </tr>
        <tr>
            <td>Require signed LogoutResponse:</td>
            <td>
                <form:select path="requireLogoutResponseSigned" multiple="false" disabled="true">
                    <form:option value="true">Yes</form:option>
                    <form:option value="false">No</form:option>
                </form:select>
            </td>
        </tr>
        <tr>
            <td>Require signed ArtifactResolve:</td>
            <td>
                <form:select path="requireArtifactResolveSigned" multiple="false" disabled="true">
                    <form:option value="true">Yes</form:option>
                    <form:option value="false">No</form:option>
                </form:select>
            </td>
        </tr>

        <c:if test="${metadata.local eq true}">

            <tr>
                <td>&nbsp;</td>
            </tr>

            <tr>
                <td>Instructions:</td>
                <td>
                    <strong>In order to permanently store the metadata follow these instructions:</strong>
                    <ul>
                        <li>Store metadata content in file ${storagePath}</li>
                        <li>Make sure to update your identity provider(s) with the generated metadata.</li>
                        <li>Modify bean "metadata" in your securityContext.xml and include content from the
                            configuration bellow
                        </li>
                    </ul>
                </td>
            </tr>

        </c:if>

        <tr>
            <td>&nbsp;</td>
        </tr>

        <tr>
            <td>Metadata:</td>
            <td>
                <textarea rows="15" cols="100" readonly="true"><c:out
                        value="${metadata.serializedMetadata}"/></textarea>
            </td>
        </tr>

        <c:if test="${metadata.local eq true}">

            <tr>
                <td>&nbsp;</td>
            </tr>

            <tr>
                <td>Configuration:</td>

                <td>
                    <textarea rows="15" cols="100" readonly="true"><c:out value="${metadata.configuration}"/></textarea>
                </td>
            </tr>

        </c:if>

    </table>

    <p>
        <a href="<c:url value="/saml/web/metadata"/>">&lt;&lt Back</a>
    </p>

</form:form>

</body>
</html>