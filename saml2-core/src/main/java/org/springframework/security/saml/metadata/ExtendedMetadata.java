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

import java.io.Serializable;
import java.util.Set;

/**
 * Class contains additional information describing a SAML entity. Metadata can be used both for local entities
 * (= the ones accessible as part of the deployed application using the SAML Extension) and remove entities (= the ones
 * user can interact with like IDPs).
 *
 * @author Vladimir Schaefer
 */
public class ExtendedMetadata implements Serializable, Cloneable {

    /**
     * Setting of the value determines whether the entity is deployed locally (hosted on the current installation) or
     * whether it's an entity deployed elsewhere.
     */
    private boolean local = false;

    /**
     * Local alias of the entity used for construction of well-known metadata address and determining target
     * entity from incoming requests.
     */
    private String alias;

    /**
     * When true IDP discovery will be invoked before SSO.
     */
    private boolean idpDiscoveryEnabled = false;

    /**
     * URL of the IDP Discovery service user should be redirected to upon request to determine which IDP to use.
     */
    private String idpDiscoveryURL;

    /**
     * Indicates whether Enhanced Client/Proxy profile should be used for requests which support it.
     */
    private boolean ecpEnabled = false;

    /**
     * Profile used for trust verification, MetaIOP by default. Only relevant for local entities.
     */
    private String securityProfile;

    /**
     * Key (stored in the local keystore) used for signing/verifying signature of messages sent/coming from this
     * entity. For local entities private key must be available, for remote entities only public key is required.
     */
    private String signingKey;

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
     * Keys used as anchors for trust verification when PKIX mode is enabled for the local entity. In case no keys are specified
     * all keys in the keyStore will be treated as trusted.
     */
    private Set<String> trustedKeys;

    /**
     * SAML specification mandates that incoming LogoutRequests must be authenticated.
     */
    private boolean requireLogoutRequestSigned = true;

    private boolean requireLogoutResponseSigned;

    private boolean requireArtifactResolveSigned;

    /**
     * Security profile to use for this local entity - MetaIOP (default) or PKIX.
     *
     * @return profile
     */
    public String getSecurityProfile() {
        return securityProfile;
    }

    /**
     * Sets profile used for verification of signatures, encryption and TLS. The following profiles are available:
     * <p/>
     * MetaIOP profile (by default):
     * <br/>
     * Uses cryptographic data from the metadata document of the entity in question. No checks for validity
     * or revocation of certificates is done in this mode. All keys must be known in advance.
     * <p/>
     * PKIX profile:
     * <br/>
     * Signatures are deemed as trusted when credential can be verified using PKIX with trusted keys of the peer
     * configured as trusted anchors. Same set of trusted keys is used for server verification in TLS connections.
     *
     * @param securityProfile profile to use - PKIX when set to "pkix", MetaIOP otherwise
     */
    public void setSecurityProfile(String securityProfile) {
        this.securityProfile = securityProfile;
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
     * <p/>
     * In case the alias is null on a local entity it must be set as a default
     * to be accessible.
     * <p/>
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
     * <p/>
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
     * <p/>
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
     * Key used to authenticate instance against remote servers.
     *
     * @return tls key
     */
    public String getTlsKey() {
        return tlsKey;
    }

    /**
     * Alias of the key used to authenticate this instance against peer servers using SSL/TLS connections. When
     * not set default credential will be used. Alias must be associated with a key containing a private key and being
     * of X509 type.
     *
     * @param tlsKey tls key
     */
    public void setTlsKey(String tlsKey) {
        this.tlsKey = tlsKey;
    }

    /**
     * Trusted keys usable for signature and server SSL/TLS verification for entities with PKIX verification enabled.
     *
     * @return trusted keys
     */
    public Set<String> getTrustedKeys() {
        return trustedKeys;
    }

    /**
     * Set of keys used as anchors for PKIX verification of messages coming from this entity. Only applicable for
     * remote entities and used when local entity has the PKIX profile enabled.
     * <p/>
     * When no trusted keys are specified all keys in the keyManager are treated as trusted.
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
     * When set to true entity is treated as locally deployed and will be able to accepte messages on endpoints determined
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

    public void setIdpDiscoveryURL(String idpDiscoveryURL) {
        this.idpDiscoveryURL = idpDiscoveryURL;
    }

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
