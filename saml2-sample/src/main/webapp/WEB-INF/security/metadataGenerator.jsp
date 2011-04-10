<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <title>Spring Security SAML Extension - Metadata</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body>

<h1>Metadata generation</h1>

<p>
    <a href="<c:url value="/saml/web/metadata"/>">&lt;&lt Back</a>
</p>

<p>
    Generates a new metadata for service provider. Output can be used to configure your securityContext.xml descriptor.
</p>

<form:form commandName="metadata" action="create">
    <table width="700">

        <tr>
            <td>Store for the current session:</td>
            <td>
                <form:select path="store" multiple="false">
                    <form:option value="true">Yes</form:option>
                    <form:option value="false">No</form:option>
                </form:select>
            </td>
            <td class="error"><form:errors path="store"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>When set to true the generated metadata will be stored in the local metadata manager. The value
                    will be available
                    only until restart of the application server.
                </small>
            </td>
        </tr>

        <tr>
            <td>&nbsp;</td>
        </tr>

        <tr>
            <td>Entity ID:</td>
            <td><form:input path="entityId"/></td>
            <td class="error"><form:errors path="entityId"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>Entity ID is a unique identifier for an identity or service provider. Value is included in the
                    generated metadata.
                </small>
            </td>
        </tr>
        <tr>
            <td>Entity base URL:</td>
            <td><form:input path="baseURL"/></td>
            <td class="error"><form:errors path="baseURL"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>Base to generate URLs for this server. For example: https://myServer:443/saml-app. The public
                    address your server will be accessed from should be used here.
                </small>
            </td>
        </tr>
        <tr>
            <td>Entity alias:</td>
            <td><form:input path="alias"/></td>
            <td class="error"><form:errors path="alias"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>Alias is an internal mechanism allowing collocating multiple service providers on one server.
                    Alias must be unique.
                </small>
            </td>
        </tr>
        <tr>
            <td>Security profile:</td>
            <td>
                <form:select path="securityProfile" multiple="false">
                    <form:option value="metaiop">MetaIOP</form:option>
                    <form:option value="pkix">PKIX</form:option>
                </form:select>
            </td>
            <td class="error"><form:errors path="securityProfile"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>
                    <p>Security profile determines how is trust of signature, encryption and SSL/TLS credentials handled. In
                    MetaIOP mode credential is deemed valid when it's declared in the metadata document of the peer entity. No
                    validation of the credentials is made. The value is recommended as a default.
                    <p>PKIX profile verifies credentials against a set of trust anchors. By default certificates present in the
                    metadata are treated as trust anchors together with the additional selected trusted keys.
                </small>
            </td>
        </tr>

        <tr>
            <td>&nbsp;</td>
        </tr>

        <tr>
            <td>Signing key:</td>
            <td><form:select path="signingKey" items="${availableKeys}"/></td>
            <td class="error"><form:errors path="signingKey"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>Key used for digital signatures of SAML messages.</small>
            </td>
        </tr>

        <tr>
            <td>Encryption key:</td>
            <td><form:select path="encryptionKey" items="${availableKeys}"/></td>
            <td class="error"><form:errors path="encryptionKey"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>Key used for digital encryption of SAML messages.</small>
            </td>
        </tr>

        <tr>
            <td>SSL/TLS key:</td>
            <td><form:select path="tlsKey" items="${availableKeys}"/></td>
            <td class="error"><form:errors path="tlsKey"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>Key used to authenticate this instance for SSL/TLS connections.</small>
            </td>
        </tr>

        <tr>
            <td>Sign metadata:</td>
            <td>
                <form:select path="signMetadata" multiple="false">
                    <form:option value="true">Yes</form:option>
                    <form:option value="false">No</form:option>
                </form:select>
            </td>
            <td><form:errors path="signMetadata"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>If true the generated metadata will be digitally signed using the specified signature key.
                </small>
            </td>
        </tr>

        <tr>
            <td>&nbsp;</td>
        </tr>

        <tr>
            <td>Sign sent AuthNRequests:</td>
            <td>
                <form:select path="requestSigned" multiple="false">
                    <form:option value="true">Yes</form:option>
                    <form:option value="false">No</form:option>
                </form:select>
            </td>
            <td class="error"><form:errors path="requestSigned"/></td>
        </tr>
        <tr>
            <td>Require signed authentication Assertion:</td>
            <td>
                <form:select path="wantAssertionSigned" multiple="false">
                    <form:option value="true">Yes</form:option>
                    <form:option value="false">No</form:option>
                </form:select>
            </td>
            <td class="error"><form:errors path="wantAssertionSigned"/></td>
        </tr>
        <tr>
            <td>Require signed LogoutRequest:</td>
            <td>
                <form:select path="requireLogoutRequestSigned" multiple="false">
                    <form:option value="true">Yes</form:option>
                    <form:option value="false">No</form:option>
                </form:select>
            </td>
            <td class="error"><form:errors path="requireLogoutRequestSigned"/></td>
        </tr>
        <tr>
            <td>Require signed LogoutResponse:</td>
            <td>
                <form:select path="requireLogoutResponseSigned" multiple="false">
                    <form:option value="true">Yes</form:option>
                    <form:option value="false">No</form:option>
                </form:select>
            </td>
            <td class="error"><form:errors path="requireLogoutResponseSigned"/></td>
        </tr>
        <tr>
            <td>Require signed ArtifactResolve:</td>
            <td>
                <form:select path="requireArtifactResolveSigned" multiple="false">
                    <form:option value="true">Yes</form:option>
                    <form:option value="false">No</form:option>
                </form:select>
            </td>
            <td class="error"><form:errors path="requireArtifactResolveSigned"/></td>
        </tr>

        <tr>
            <td colspan="2">
                <br/>
                <input type="submit" value="Generate metadata"/>
            </td>
        </tr>
    </table>
</form:form>

<p>
    <a href="<c:url value="/saml/web/metadata"/>">&lt;&lt Back</a>
</p>

</body>
</html>