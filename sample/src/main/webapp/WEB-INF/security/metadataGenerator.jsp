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
                        <div class="post-title"><h2 class="label label-green">Metadata generation</h2></div>
                        <p class="quiet large">Generates new metadata for service provider. Output can be used to configure your
                            securityContext.xml descriptor.</p>
                        <div class="post-body">
                            <p><a href="<c:url value="/saml/web/metadata"/>">&lt;&lt Back</a></p>
                            <form:form commandName="metadata" action="create">
                            <table>
                            <tr>
                                <td><label for="store">Store for the current session:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="store"/>
                                    <form:select id="store" path="store" multiple="false">
                                        <form:option value="true">Yes</form:option>
                                        <form:option value="false">No</form:option>
                                    </form:select>
                                </td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <small>When set to true the generated metadata will be stored in the local metadata manager. The value
                                        will be available
                                        only until restart of the application server.
                                    </small>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="entityId">Entity ID:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="entityId"/>
                                    <form:input cssClass="text" id="entityId" path="entityId"/>
                                </td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <small>Entity ID is a unique identifier for an identity or service provider. Value is included in the
                                        generated metadata.
                                    </small>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="baseURL">Entity base URL:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="baseURL"/>
                                    <form:input cssClass="text" id="baseURL" path="baseURL"/>
                                </td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <small>Base to generate URLs for this server. For example: https://myServer:443/saml-app. The public
                                        address your server will be accessed from should be used here.
                                    </small>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="alias">Entity alias:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="alias"/>
                                    <form:input cssClass="text" id="alias" path="alias"/>
                                </td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <small>Alias is an internal mechanism allowing collocating multiple service providers on one server.
                                        When set, alias must be unique.
                                    </small>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="signingKey">Signing key:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="signingKey"/>
                                    <form:select path="signingKey" id="signingKey" items="${availableKeys}"/>
                                </td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <small>Key used for digital signatures of SAML messages. Public key will be included in the metadata.</small>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="encryptionKey">Encryption key:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="encryptionKey"/>
                                    <form:select path="encryptionKey" id="encryptionKey" items="${availableKeys}"/>
                                </td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <small>Key used for digital encryption of SAML messages. Public key will be included in the metadata.</small>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="securityProfile">Signature security profile:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="securityProfile"/>
                                    <form:select path="securityProfile" id="securityProfile" multiple="false">
                                        <form:option value="metaiop">MetaIOP</form:option>
                                        <form:option value="pkix">PKIX</form:option>
                                    </form:select>
                                </td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <small>
                                        Security profile determines how is trust of digital signatures handled:
                                        <ul>
                                            <li>
                                                In <a href="http://wiki.oasis-open.org/security/SAML2MetadataIOP">MetaIOP</a> mode certificate is
                                                deemed
                                                valid when it's declared in the metadata or extended metadata of the peer entity. No validation of
                                                the certificate is
                                                performed (e.g. revocation) and no certificate chains are evaluated. The value is recommended as a
                                                default.
                                            </li>
                                            <li>
                                                PKIX profile verifies credentials against a set of trust anchors. Certificates present in the
                                                metadata or extended metadata of the peer entity are treated as trust anchors, together with all
                                                keys in
                                                the keystore. Certificate chains are verified in this mode.
                                            </li>
                                        </ul>
                                    </small>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="sslSecurityProfile">SSL/TLS security profile:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="sslSecurityProfile"/>
                                    <form:select path="sslSecurityProfile" id="sslSecurityProfile" multiple="false">
                                        <form:option value="pkix">PKIX</form:option>
                                        <form:option value="metaiop">MetaIOP</form:option>
                                    </form:select>
                                </td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <small>
                                        SSL/TLS Security profile determines how is trust of peer's SSL/TLS certificate (e.g. during Artifact
                                        resolution) handled:
                                        <ul>
                                            <li>
                                                PKIX profile verifies peer's certificate against a set of trust anchors. All certificates defined in
                                                metadata,
                                                extended metadata or present in the keystore are considered as trusted anchors (certification
                                                authorities)
                                                for PKIX validation.
                                            </li>
                                            <li>
                                                In MetaIOP mode server's SSL/TLS certificate is trusted when it's explicitly declared in metadata or
                                                extended metadata of
                                                the peer.
                                            </li>
                                        </ul>
                                    </small>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="sslHostnameVerification">SSL/TLS hostname verification:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="sslHostnameVerification"/>
                                    <form:select path="sslHostnameVerification" id="sslHostnameVerification" multiple="false">
                                        <form:option value="default">Standard hostname verifier</form:option>
                                        <form:option
                                                value="defaultAndLocalhost">Standard hostname verifier (skips verification for localhost)</form:option>
                                        <form:option value="strict">Strict hostname verifier</form:option>
                                        <form:option value="allowAll">Disable hostname verification (allow all)</form:option>
                                    </form:select>
                                </td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <small>Algorithm for verification of match between hostname in URL and hostname in the presented certificate.
                                    </small>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="tlsKey">SSL/TLS client authentication:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="tlsKey"/>
                                    <form:select path="tlsKey" id="tlsKey">
                                        <form:option value="">None</form:option>
                                        <form:options items="${availableKeys}"/>
                                    </form:select>
                                </td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <small>Key used to authenticate this instance for SSL/TLS connections.</small>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="signMetadata">Sign metadata:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="signMetadata"/>
                                    <form:select path="signMetadata" id="signMetadata" multiple="false">
                                        <form:option value="true">Yes</form:option>
                                        <form:option value="false">No</form:option>
                                    </form:select>
                                </td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <small>If true the generated metadata will be digitally signed using the specified signature key.
                                    </small>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="signingAlgorithm">Signing algorithm:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="signingAlgorithm"/>
                                    <form:input cssClass="text" id="signingAlgorithm" path="signingAlgorithm"/>
                                </td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <small>Algorithm used for creation of digital signature on metadata. Typical values are
                                        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                                        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" and "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
                                    </small>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="requestSigned">Sign sent AuthNRequests:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="requestSigned"/>
                                    <form:select path="requestSigned" id="requestSigned" multiple="false">
                                        <form:option value="true">Yes</form:option>
                                        <form:option value="false">No</form:option>
                                    </form:select>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="wantAssertionSigned">Require signed authentication Assertion:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="wantAssertionSigned"/>
                                    <form:select path="wantAssertionSigned" id="wantAssertionSigned" multiple="false">
                                        <form:option value="true">Yes</form:option>
                                        <form:option value="false">No</form:option>
                                    </form:select>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="requireLogoutRequestSigned">Require signed LogoutRequest:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="requireLogoutRequestSigned"/>
                                    <form:select path="requireLogoutRequestSigned" id="requireLogoutRequestSigned" multiple="false">
                                        <form:option value="true">Yes</form:option>
                                        <form:option value="false">No</form:option>
                                    </form:select>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="requireLogoutResponseSigned">Require signed LogoutResponse:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="requireLogoutResponseSigned"/>
                                    <form:select path="requireLogoutResponseSigned" id="requireLogoutResponseSigned" multiple="false">
                                        <form:option value="true">Yes</form:option>
                                        <form:option value="false">No</form:option>
                                    </form:select>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="requireArtifactResolveSigned">Require signed ArtifactResolve:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="requireArtifactResolveSigned"/>
                                    <form:select path="requireArtifactResolveSigned" id="requireArtifactResolveSigned" multiple="false">
                                        <form:option value="true">Yes</form:option>
                                        <form:option value="false">No</form:option>
                                    </form:select>
                                </td>
                            </tr>
                            <tr>
                                <td><label>Single sign-on bindings:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="ssoBindings"/>
                                    <form:errors cssClass="error" element="div" path="ssoDefaultBinding"/>
                                    <table>
                                        <tr>
                                            <th>Default</th>
                                            <th>Included</th>
                                            <th>Name</th>
                                        </tr>
                                        <tr>
                                            <td><form:radiobutton path="ssoDefaultBinding"
                                                                  value="<%= MetadataController.AllowedSSOBindings.SSO_POST %>"/></td>
                                            <td><form:checkbox path="ssoBindings" value="<%= MetadataController.AllowedSSOBindings.SSO_POST %>"
                                                               id="sso_0"/></td>
                                            <td><label for="sso_0">SSO HTTP-POST</label></td>
                                        </tr>
                                        <tr>
                                            <td><form:radiobutton path="ssoDefaultBinding"
                                                                  value="<%= MetadataController.AllowedSSOBindings.SSO_ARTIFACT %>"/></td>
                                            <td><form:checkbox path="ssoBindings" value="<%= MetadataController.AllowedSSOBindings.SSO_ARTIFACT %>"
                                                               id="sso_1"/></td>
                                            <td><label for="sso_1">SSO Artifact</label></td>
                                        </tr>
                                        <tr>
                                            <td><form:radiobutton path="ssoDefaultBinding"
                                                                  value="<%= MetadataController.AllowedSSOBindings.SSO_PAOS %>"/></td>
                                            <td><form:checkbox path="ssoBindings" value="<%= MetadataController.AllowedSSOBindings.SSO_PAOS %>"
                                                               id="sso_2"/></td>
                                            <td><label for="sso_2">SSO PAOS</label></td>
                                        </tr>
                                        <tr>
                                            <td><form:radiobutton path="ssoDefaultBinding"
                                                                  value="<%= MetadataController.AllowedSSOBindings.HOKSSO_ARTIFACT %>"/></td>
                                            <td><form:checkbox path="ssoBindings"
                                                               value="<%= MetadataController.AllowedSSOBindings.HOKSSO_ARTIFACT %>"
                                                               id="sso_3"/></td>
                                            <td><label for="sso_3">HoK SSO Artifact</label></td>
                                        </tr>
                                        <tr>
                                            <td><form:radiobutton path="ssoDefaultBinding"
                                                                  value="<%= MetadataController.AllowedSSOBindings.HOKSSO_POST %>"/></td>
                                            <td><form:checkbox path="ssoBindings" value="<%= MetadataController.AllowedSSOBindings.HOKSSO_POST %>"
                                                               id="sso_4"/></td>
                                            <td><label for="sso_4">HoK SSO HTTP-POST</label></td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                            <tr>
                                <td><label>Supported NameIDs:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="nameID"/>
                                    <table>
                                        <tr>
                                            <td><form:checkbox path="nameID" value="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                                                               id="nameid_0"/></td>
                                            <td><label for="nameid_0">E-Mail</label></td>
                                        </tr>
                                        <tr>
                                            <td><form:checkbox path="nameID" value="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
                                                               id="nameid_1"/></td>
                                            <td><label for="nameid_1">Transient</label></td>
                                        </tr>
                                        <tr>
                                            <td><form:checkbox path="nameID" value="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                                                               id="nameid_2"/></td>
                                            <td><label for="nameid_2">Persistent</label></td>
                                        </tr>
                                        <tr>
                                            <td><form:checkbox path="nameID" value="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                                                               id="nameid_3"/></td>
                                            <td><label for="nameid_3">Unspecified</label></td>
                                        </tr>
                                        <tr>
                                            <td><form:checkbox path="nameID" value="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
                                                               id="nameid_4"/></td>
                                            <td><label for="nameid_4">X509 Subject</label></td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="includeDiscovery">Enable IDP discovery profile:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="includeDiscovery"/>
                                    <form:select path="includeDiscovery" id="includeDiscovery" multiple="false">
                                        <form:option value="true">Yes</form:option>
                                        <form:option value="false">No</form:option>
                                    </form:select>
                                </td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <small>
                                        <a href="http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.pdf">Discovery
                                            profile</a> enables service provider to determine which identity provider should be used
                                        for a particular user. Spring Security SAML contains it's own discovery service which presents
                                        user with an IDP list to select from.
                                    </small>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="customDiscoveryURL">Custom URL for IDP discovery:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="customDiscoveryURL"/>
                                    <form:input cssClass="text" id="customDiscoveryURL" path="customDiscoveryURL"/>
                                </td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <small>When not set local IDP discovery URL is automatically generated when IDP discovery is enabled.</small>
                                </td>
                            </tr>
                            <tr>
                                <td><label for="includeDiscoveryExtension">Include IDP discovery extension in metadata:</label></td>
                                <td>
                                    <form:errors cssClass="error" element="div" path="includeDiscoveryExtension"/>
                                    <form:select path="includeDiscoveryExtension" id="includeDiscoveryExtension" multiple="false">
                                        <form:option value="true">Yes</form:option>
                                        <form:option value="false">No</form:option>
                                    </form:select>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <br/>
                                    <input type="submit" class="button" value="Generate metadata"/>
                                </td>
                            </tr>
                            </table>
                            </form:form>
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