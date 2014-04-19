<%@ page import="org.springframework.security.saml.web.MetadataController" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <title>Spring Security SAML Extension - Metadata</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <style type="text/css">
        .error {
            color : red;
        }
    </style>
</head>
<body>

<h1>Metadata generation</h1>

<p>
    <a href="<c:url value="/saml/web/metadata"/>">&lt;&lt Back</a>
</p>

Generates new metadata for service provider. Output can be used to configure your securityContext.xml descriptor.

<form:form commandName="metadata" action="create">
    <table>

        <tr>
            <td colspan="2">
                <br/>
                <input type="submit" value="Generate metadata"/>
            </td>
        </tr>

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
                    Security profile determines how is trust of digital signatures handled:
                    <ul>
                    <li>
                        In <a href="http://wiki.oasis-open.org/security/SAML2MetadataIOP">MetaIOP</a> mode certificate is deemed
                        valid when it's declared in the metadata or extended metadata of the peer entity. No validation of the certificate is
                        performed (e.g. revocation) and no certificate chains are evaluated. The value is recommended as a default.
                    </li>
                    <li>
                        PKIX profile verifies credentials against a set of trust anchors. Certificates present in the
                        metadata or extended metadata of the peer entity are treated as trust anchors, together with all keys in
                        the keystore. Certificate chains are verified in this mode.
                    </li>
                    </ul>
                </small>
            </td>
        </tr>

        <tr>
            <td>Signing key:</td>
            <td><form:select path="signingKey" items="${availableKeys}"/></td>
            <td class="error"><form:errors path="signingKey"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>Key used for digital signatures of SAML messages. Public key will be included in the metadata.</small>
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
                <small>Key used for digital encryption of SAML messages. Public key will be included in the metadata.</small>
            </td>
        </tr>

        <tr>
            <td>&nbsp;</td>
        </tr>

        <tr>
            <td>SSL/TLS Security profile:</td>
            <td>
                <form:select path="sslSecurityProfile" multiple="false">
                    <form:option value="pkix">PKIX</form:option>
                    <form:option value="metaiop">MetaIOP</form:option>
                </form:select>
            </td>
            <td class="error"><form:errors path="sslSecurityProfile"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>
                    SSL/TLS Security profile determines how is trust of peer's SSL/TLS certificate (e.g. during Artifact resolution) handled:
                    <ul>
                    <li>
                    PKIX profile verifies peer's certificate against a set of trust anchors. All certificates defined in metadata,
                    extended metadata or present in the keystore are considered as trusted anchors (certification authorities)
                    for PKIX validation.
                    </li>
                    <li>
                    In MetaIOP mode server's SSL/TLS certificate is trusted when it's explicitly declared in metadata or extended metadata of
                    the peer.
                    </li>
                    </ul>
                </small>
            </td>
        </tr>

        <tr>
            <td>SSL/TLS Hostname Verification:</td>
            <td>
                <form:select path="sslHostnameVerification" multiple="false">
                    <form:option value="default">Standard hostname verifier</form:option>
                    <form:option value="defaultAndLocalhost">Standard hostname verifier (skips verification for localhost)</form:option>
                    <form:option value="strict">Strict hostname verifier</form:option>
                    <form:option value="allowAll">Disable hostname verification (allow all)</form:option>
                </form:select>
            </td>
            <td class="error"><form:errors path="sslHostnameVerification"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>Algorithm for verification of match between hostname in URL and hostname in the presented certificate.</small>
            </td>
        </tr>

        <tr>
            <td>SSL/TLS Client authentication:</td>
            <td>
                <form:select path="tlsKey">
                    <form:option value="">None</form:option>
                    <form:options items="${availableKeys}"/>
                </form:select>
            </td>
            <td class="error"><form:errors path="tlsKey"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>Key used to authenticate this instance for SSL/TLS connections.</small>
            </td>
        </tr>

        <tr>
            <td>&nbsp;</td>
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
            <td>&nbsp;</td>
        </tr>

        <tr>
            <td>Single sign-on bindings:</td>
            <td>
                <table>
                    <tr><th>Default</th><th>Included</th><th>Name</th></tr>
                    <tr>
                        <td><form:radiobutton path="ssoDefaultBinding" value="<%= MetadataController.AllowedSSOBindings.SSO_ARTIFACT %>" /></td>
                        <td><form:checkbox path="ssoBindings" value="<%= MetadataController.AllowedSSOBindings.SSO_ARTIFACT %>" id="sso_0"/></td>
                        <td><label for="sso_0">SSO Artifact</label></td>
                    </tr>
                    <tr>
                        <td><form:radiobutton path="ssoDefaultBinding" value="<%= MetadataController.AllowedSSOBindings.SSO_POST %>" /></td>
                        <td><form:checkbox path="ssoBindings" value="<%= MetadataController.AllowedSSOBindings.SSO_POST %>" id="sso_1"/></td>
                        <td><label for="sso_1">SSO HTTP-POST</label></td>
                    </tr>
                    <tr>
                        <td><form:radiobutton path="ssoDefaultBinding" value="<%= MetadataController.AllowedSSOBindings.SSO_PAOS %>" /></td>
                        <td><form:checkbox path="ssoBindings" value="<%= MetadataController.AllowedSSOBindings.SSO_PAOS %>" id="sso_2"/></td>
                        <td><label for="sso_2">SSO PAOS</label></td>
                    </tr>
                    <tr>
                        <td><form:radiobutton path="ssoDefaultBinding" value="<%= MetadataController.AllowedSSOBindings.HOKSSO_ARTIFACT %>" /></td>
                        <td><form:checkbox path="ssoBindings" value="<%= MetadataController.AllowedSSOBindings.HOKSSO_ARTIFACT %>" id="sso_3"/></td>
                        <td><label for="sso_3">HoK SSO Artifact</label></td>
                    </tr>
                    <tr>
                        <td><form:radiobutton path="ssoDefaultBinding" value="<%= MetadataController.AllowedSSOBindings.HOKSSO_POST %>" /></td>
                        <td><form:checkbox path="ssoBindings" value="<%= MetadataController.AllowedSSOBindings.HOKSSO_POST %>" id="sso_4"/></td>
                        <td><label for="sso_4">HoK SSO HTTP-POST</label></td>
                    </tr>
                </table>
            </td>
            <td class="error">
                <form:errors path="ssoBindings"/>
                <form:errors path="ssoDefaultBinding"/>
            </td>
        </tr>

        <tr>
            <td>&nbsp;</td>
        </tr>

        <tr>
            <td>Supported NameIDs:</td>
            <td>
                <table>
                    <tr><td><form:checkbox path="nameID" value="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" id="nameid_0"/></td><td><label for="nameid_0">E-Mail</label></td></tr>
                    <tr><td><form:checkbox path="nameID" value="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" id="nameid_1"/></td><td><label for="nameid_1">Transient</label></td></tr>
                    <tr><td><form:checkbox path="nameID" value="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" id="nameid_2"/></td><td><label for="nameid_2">Persistent</label></td></tr>
                    <tr><td><form:checkbox path="nameID" value="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" id="nameid_3"/></td><td><label for="nameid_3">Unspecified</label></td></tr>
                    <tr><td><form:checkbox path="nameID" value="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName" id="nameid_4"/></td><td><label for="nameid_4">X509 Subject</label></td></tr>
                </table>
            </td>
            <td class="error"><form:errors path="nameID"/></td>
        </tr>

        <tr>
            <td>&nbsp;</td>
        </tr>

        <tr>
            <td>Enable IDP Discovery profile:</td>
            <td>
                <form:select path="includeDiscovery" multiple="false">
                    <form:option value="true">Yes</form:option>
                    <form:option value="false">No</form:option>
                </form:select>
            </td>
            <td class="error"><form:errors path="includeDiscovery"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>
                    <a href="http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.pdf">Discovery
                    profile</a> enables service provider to determine which identity provider should be used
                    for a particular user. Spring Security SAML contains it's own discovery service which presents
                    user with an IDP list to select from.
                </small>
            </td>
        </tr>

        <tr>
            <td>Custom URL for IDP Discovery:</td>
                    <td>
                <form:input path="customDiscoveryURL"/>
            </td>
            <td class="error"><form:errors path="customDiscoveryURL"/></td>
        </tr>
        <tr>
            <td></td>
            <td colspan="2">
                <small>When not set local IDP discovery URL is automatically generated when IDP discovery is enabled.</small>
            </td>
        </tr>

        <tr>
            <td>Include IDP Discovery extension in metadata:</td>
            <td>
                <form:select path="includeDiscoveryExtension" multiple="false">
                    <form:option value="true">Yes</form:option>
                    <form:option value="false">No</form:option>
                </form:select>
            </td>
            <td class="error"><form:errors path="includeDiscoveryExtension"/></td>
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