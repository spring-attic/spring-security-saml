/* Copyright 2011 Vladimir Schaefer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.saml.metadata;

import org.springframework.security.saml.SAMLConstants;

import java.io.Serializable;
import java.util.Set;

/**
 * Class contains additional information describing a SAML entity. Metadata can be used both for local entities
 * (= the ones accessible as part of the deployed application using the SAML Extension) and remote entities (= the ones
 * user can interact with like IDPs).
 *
 * @author Vladimir Schaefer
 */
public class ExtendedMetadata implements Serializable, Cloneable {

    /**
     * Setting of the value determines whether the entity is deployed locally (hosted on the current installation) or
     * whether it's an entity deployed elsewhere.
     */
    private boolean local;

    /**
     * Local alias of the entity used for construction of well-known metadata address and determining target
     * entity from incoming requests.
     */
    private String alias;

    /**
     * When true IDP discovery will be invoked before SSO. Only valid for local entities.
     */
    private boolean idpDiscoveryEnabled;

    /**
     * URL of the IDP Discovery service user should be redirected to upon request to determine which IDP to use.
     * Value can override settings in the local SP metadata. Only valid for local entities.
     */
    private String idpDiscoveryURL;

    /**
     * URL where the discovery service should send back response to our discovery request. Only valid for local
     * entities.
     */
    private String idpDiscoveryResponseURL;

    /**
     * Indicates whether Enhanced Client/Proxy profile should be used for requests which support it. Only valid for
     * local entities.
     */
    private boolean ecpEnabled;

    /**
     * Profile used for trust verification, MetaIOP by default. Only relevant for local entities.
     */
    private String securityProfile = "metaiop";

    /**
     * Profile used for SSL/TLS trust verification, PKIX by default. Only relevant for local entities.
     */
    private String sslSecurityProfile = "pkix";

    /**
     * Hostname verifier to use for verification of SSL connections, e.g. for ArtifactResolution.
     */
    private String sslHostnameVerification = "default";

    /**
     * Key (stored in the local keystore) used for signing/verifying signature of messages sent/coming from this
     * entity. For local entities private key must be available, for remote entities only public key is required.
     */
    private String signingKey;

    /**
     * Algorithm used for creation of digital signatures of this entity. At the moment only used for metadata signatures.
     * Only valid for local entities.
     */
    private String signingAlgorithm;

    /**
     * Flag indicating whether to sign metadata for this entity. Only valid for local entities.
     */
    private boolean signMetadata;

    /**
     * Name of generator for KeyInfo elements in metadata and signatures. At the moment only used for metadata signatures.
     * Only valid for local entities.
     */
    private String keyInfoGeneratorName = SAMLConstants.SAML_METADATA_KEY_INFO_GENERATOR;

    /**
     * Key (stored in the local keystore) used for encryption/decryption of messages coming/sent from this entity. For local entities
     * private key must be available, for remote entities only public key is required.
     */
    private String encryptionKey;

    /**
     * Key used for verification of SSL/TLS connections. For local entities key is included in the generated metadata when specified.
     * For remote entities key is used to for server authentication of SSL/TLS when specified and when MetaIOP security profile is used.
     */
    private String tlsKey;

    /**
     * Keys used as anchors for trust verification when PKIX mode is enabled for the local entity. In case value is null
     * all keys in the keyStore will be treated as trusted.
     */
    private Set<String> trustedKeys;

    /**
     * SAML specification mandates that incoming LogoutRequests must be authenticated.
     */
    private boolean requireLogoutRequestSigned = true;

    /**
     * Flag indicating whether incoming LogoutResposne messages must be authenticated.
     */
    private boolean requireLogoutResponseSigned;

    /**
     * If true received artifactResolve messages will require a signature, sent artifactResolve will be signed.
     */
    private boolean requireArtifactResolveSigned = true;

    /**
     * Flag indicating whether to support unsolicited responses (IDP-initialized SSO). Only valid for remote
     * entities.
     */
    private boolean supportUnsolicitedResponse = true;

    /**
     * Security profile to use for this local entity - MetaIOP (default) or PKIX.
     *
     * @return profile
     */
    public String getSecurityProfile() {
        return securityProfile;
    }

    /**
     * Sets profile used for verification of signatures and encryption. The following profiles are available:
     * <p>
     * MetaIOP profile (by default):
     * <br>
     * Uses cryptographic data from the metadata document of the entity in question. No checks for validity
     * or revocation of certificates is done in this mode. All keys must be known in advance.
     * <p>
     * PKIX profile:
     * <br>
     * Signatures are deemed as trusted when credential can be verified using PKIX with trusted keys of the peer
     * configured as trusted anchors.
     * <p>
     * This setting is only relevant for local entities.
     *
     * @param securityProfile profile to use - PKIX when set to "pkix", MetaIOP otherwise
     */
    public void setSecurityProfile(String securityProfile) {
        this.securityProfile = securityProfile;
    }

    /**
     * Security profile used for SSL/TLS connections of the local entity.
     *
     * @return profile
     */
    public String getSslSecurityProfile() {
        return sslSecurityProfile;
    }

    /**
     * Sets profile used for verification of SSL/TLS connections. The following profiles are available:
     * <p>
     * PKIX profile (by default), value "pkix":
     * <br>
     * Signatures are deemed as trusted when credential can be verified using PKIX with trusted keys of the peer
     * configured as trusted anchors.
     * <p>
     * MetaIOP profile, any other value:
     * <br>
     * Uses cryptographic data from the metadata document of the entity in question. No checks for validity
     * or revocation of certificates is done in this mode. All keys must be known in advance.
     * <p>
     * Logic is enforced in SAMLContextProviderImpl#populateSSLTrustEngine. Values are case insensitive.
     * <p>
     * This setting is only relevant for local entities.
     *
     * @param sslSecurityProfile profile to use - PKIX when set to "pkix", MetaIOP otherwise
     */
    public void setSslSecurityProfile(String sslSecurityProfile) {
        this.sslSecurityProfile = sslSecurityProfile;
    }

    /**
     * Hostname verifier for SSL connections.
     *
     * @return hostname verifier
     */
    public String getSslHostnameVerification() {
        return sslHostnameVerification;
    }

    /**
     * Sets hostname verifier to use for verification of SSL connections. The following values are available:
     * <p>
     * default: org.apache.commons.ssl.HostnameVerifier.DEFAULT
     * <br>
     * defaultAndLocalhost: org.apache.commons.ssl.HostnameVerifier.DEFAULT_AND_LOCALHOST
     * <br>
     * strict: org.apache.commons.ssl.HostnameVerifier.STRICT
     * <br>
     * allowAll: org.apache.commons.ssl.HostnameVerifier.ALLOW_ALL, doesn't perform any validation
     * <p>
     * Logic is enforced in SAMLContextProviderImpl#populateSSLHostnameVerifier. Values are case insensitive.
     * Unrecognized value revert to default setting.
     * <p>
     * This setting is only relevant for local entities.
     *
     * @param sslHostnameVerification hostname verification type flag
     */
    public void setSslHostnameVerification(String sslHostnameVerification) {
        this.sslHostnameVerification = sslHostnameVerification;
    }

    /**
     * Returns alias. Value should be null for remote entities.
     *
     * @return alias
     */
    public String getAlias() {
        return alias;
    }

    /**
     * Alias is used to identify a destination entity as part of the URL. It only applies to local entities. Only
     * ASCII characters can be used as alias.
     * <p>
     * In case the alias is null on a local entity it must be set as a default
     * to be accessible.
     * <p>
     * Alias must be unique for each local entityId.
     *
     * @param alias alias value
     */
    public void setAlias(String alias) {
        this.alias = alias;
    }

    /**
     * Signing key used for signing messages or verifying signatures of this entity.
     *
     * @return signing key, default if null
     */
    public String getSigningKey() {
        return signingKey;
    }

    /**
     * Sets signing key to be used for interaction with the current entity. In case the entity is local the keyStore
     * must contain a private and public key with the given name. For remote entities only public key is required.
     * <p>
     * Value can be used to override credential contained in the remote metadata.
     *
     * @param signingKey key for creation/verification of signatures
     */
    public void setSigningKey(String signingKey) {
        this.signingKey = signingKey;
    }

    /**
     * Encryption key used for encrypting messages send to the remote entity or decrypting data sent to the local one.
     *
     * @return encryption key, default if null
     */
    public String getEncryptionKey() {
        return encryptionKey;
    }

    /**
     * Sets encryption key to be used for interaction with the current entity. In case the entity is local the keyStore
     * must contain a private key with the given name which will be used for decryption incoming message.
     * For remote entities only public key is required and will be used for encryption of the sent data.
     * <p>
     * Value can be used to override credential contained in the remote metadata.
     *
     * @param encryptionKey key for creation/verification of signatures
     */
    public void setEncryptionKey(String encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    /**
     * Flag indicating whether entity in question requires logout request to be signed.
     *
     * @return signature flag
     */
    public boolean isRequireLogoutRequestSigned() {
        return requireLogoutRequestSigned;
    }

    /**
     * If true logoutRequests received will require a signature, sent logoutRequests will be signed.
     *
     * @param requireLogoutRequestSigned logout request signature flag
     */
    public void setRequireLogoutRequestSigned(boolean requireLogoutRequestSigned) {
        this.requireLogoutRequestSigned = requireLogoutRequestSigned;
    }

    /**
     * Flag indicating whether entity in question requires logout response to be signed.
     *
     * @return signature flag
     */
    public boolean isRequireLogoutResponseSigned() {
        return requireLogoutResponseSigned;
    }

    /**
     * If true logoutResponses received will require a signature, sent logoutResponses will be signed.
     *
     * @param requireLogoutResponseSigned logout response signature flag
     */
    public void setRequireLogoutResponseSigned(boolean requireLogoutResponseSigned) {
        this.requireLogoutResponseSigned = requireLogoutResponseSigned;
    }

    /**
     * Flag indicating whether entity in question requires artifact resolve messages to be signed.
     *
     * @return signature flag
     */
    public boolean isRequireArtifactResolveSigned() {
        return requireArtifactResolveSigned;
    }

    /**
     * If true received artifactResolve messages will require a signature, sent artifactResolve will be signed.
     *
     * @param requireArtifactResolveSigned artifact resolve signature flag
     */
    public void setRequireArtifactResolveSigned(boolean requireArtifactResolveSigned) {
        this.requireArtifactResolveSigned = requireArtifactResolveSigned;
    }

    /**
     * Key used to authenticate instance against remote peers when specified on local entity. When specified on
     * remote entity the key is added as a trust anchor during communication with the entity using SSL/TLS.
     *
     * @return tls key
     */
    public String getTlsKey() {
        return tlsKey;
    }

    /**
     * For local entities denotes alias of the key used to authenticate this instance against peer servers using SSL/TLS connections. When
     * not set no key will be available for client authentication. Alias must be associated with a key containing a private key and being
     * of X509 type. For remote entities denotes key to be used as a trust anchor for SSL/TLS connections.
     *
     * @param tlsKey tls key
     */
    public void setTlsKey(String tlsKey) {
        this.tlsKey = tlsKey;
    }

    /**
     * Trusted keys usable for signature and server SSL/TLS verification for entities with PKIX verification enabled.
     * Value is ignored when PKIX security is not enabled. In case value is null all keys in the keyStore will be
     * treated as trusted.
     *
     * @return trusted keys
     */
    public Set<String> getTrustedKeys() {
        return trustedKeys;
    }

    /**
     * Set of keys used as anchors for PKIX verification of messages coming from this entity. Only applicable for
     * remote entities and used when local entity has the PKIX profile enabled.
     * <p>
     * When no trusted keys are specified all keys in the keyManager are treated as trusted.
     * <p>
     * This setting is only relevant for remote entities.
     *
     * @param trustedKeys keys
     */
    public void setTrustedKeys(Set<String> trustedKeys) {
        this.trustedKeys = trustedKeys;
    }

    public boolean isLocal() {
        return local;
    }

    /**
     * When set to true entity is treated as locally deployed and will be able to accept messages on endpoints determined
     * by the selected alias.
     *
     * @param local true when entity is deployed locally
     */
    public void setLocal(boolean local) {
        this.local = local;
    }

    public String getIdpDiscoveryURL() {
        return idpDiscoveryURL;
    }

    /**
     * URL to invoke while initializing IDP Discovery protocol for the local SP.
     *
     * @param idpDiscoveryURL IDP discovery URL
     */
    public void setIdpDiscoveryURL(String idpDiscoveryURL) {
        this.idpDiscoveryURL = idpDiscoveryURL;
    }

    public String getIdpDiscoveryResponseURL() {
        return idpDiscoveryResponseURL;
    }

    /**
     * When set our local IDP Discovery implementation will send response back to Service Provider on this address.
     * Value should be set in situations when public address of the SP differs from values seen by the application sever.
     *
     * @param idpDiscoveryResponseURL discovery response URL
     */
    public void setIdpDiscoveryResponseURL(String idpDiscoveryResponseURL) {
        this.idpDiscoveryResponseURL = idpDiscoveryResponseURL;
    }

    /**
     * When true IDP discovery will be invoked before initializing WebSSO, unless IDP is already specified inside
     * SAMLContext.
     *
     * @return true when idp discovery is enabled
     */
    public boolean isIdpDiscoveryEnabled() {
        return idpDiscoveryEnabled;
    }

    public void setIdpDiscoveryEnabled(boolean idpDiscoveryEnabled) {
        this.idpDiscoveryEnabled = idpDiscoveryEnabled;
    }

    public void setEcpEnabled(boolean ecpEnabled) {
        this.ecpEnabled = ecpEnabled;
    }

    public boolean isEcpEnabled() {
        return ecpEnabled;
    }

    /**
     * Gets the signing algorithm to use when signing the SAML messages.
     * This can be used, for example, when a strong algorithm is required (e.g. SHA 256 instead of SHA 128).
     *
     * Value only applies to local entities.
     *
     * At the moment the value is only used for signatures on metadata.
     *
     * @return A signing algorithm URI, if set. Otherwise returns null.
     * @see org.opensaml.xml.signature.SignatureConstants
     */
    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    /**
     * Sets the signing algorithm to use when signing the SAML messages.
     * This can be used, for example, when a strong algorithm is required (e.g. SHA 256 instead of SHA 128).
     * If this property is null, then the {@link org.opensaml.xml.security.credential.Credential} default algorithm will be used instead.
     *
     * Value only applies to local entities.
     *
     * At the moment the value is only used for signatures on metadata.
     *
     * Typical values are:
     * http://www.w3.org/2000/09/xmldsig#rsa-sha1
     * http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
     * http://www.w3.org/2001/04/xmldsig-more#rsa-sha512
     *
     * @param signingAlgorithm The new signing algorithm to use
     * @see org.opensaml.xml.signature.SignatureConstants
     */
    public void setSigningAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }

    /**
     * Sets KeyInfoGenerator used to create KeyInfo elements in metadata and digital signatures. Only valid
     * for local entities.
     *
     * @param keyInfoGeneratorName generator name
     */
    public void setKeyInfoGeneratorName(String keyInfoGeneratorName) {
        this.keyInfoGeneratorName = keyInfoGeneratorName;
    }

    /**
     * Name of the KeyInfoGenerator registered at default KeyInfoGeneratorManager. Used to generate
     * KeyInfo elements in metadata and signatures.
     *
     * @return key info generator name
     * @see org.opensaml.Configuration#getGlobalSecurityConfiguration()
     * @see org.opensaml.xml.security.SecurityConfiguration#getKeyInfoGeneratorManager()
     */
    public String getKeyInfoGeneratorName() {
        return keyInfoGeneratorName;
    }

    /**
     * Flag indicating whether local metadata will be digitally signed.
     *
     * @return metadata signing flag
     */
    public boolean isSignMetadata() {
        return signMetadata;
    }

    /**
     * When set to true metadata generated for this entity will be digitally signed by the signing certificate.
     * Only applies to local entities.
     *
     * @param signMetadata metadata signing flag
     */
    public void setSignMetadata(boolean signMetadata) {
        this.signMetadata = signMetadata;
    }

    /**
     * @return true when system should accept unsolicited response messages from this remote entity
     */
    public boolean isSupportUnsolicitedResponse() {
        return supportUnsolicitedResponse;
    }

    /**
     * When set to true system will support reception of Unsolicited SAML Response messages (IDP-initialized single
     * sign-on) from this remote entity. When disabled such messages will be rejected.
     *
     * Unsolicited Responses are by default enabled.
     *
     * @param supportUnsolicitedResponse unsolicited response flag
     */
    public void setSupportUnsolicitedResponse(boolean supportUnsolicitedResponse) {
        this.supportUnsolicitedResponse = supportUnsolicitedResponse;
    }

    /**
     * Clones the existing metadata object.
     *
     * @return clone of the metadata
     */
    @Override
    public ExtendedMetadata clone() {
        try {
            return (ExtendedMetadata) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException("Extended metadata not cloneable", e);
        }
    }

}