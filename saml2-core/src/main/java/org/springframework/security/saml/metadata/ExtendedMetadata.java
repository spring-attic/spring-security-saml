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

/**
 * Class contains additional information describing a SAML entity. Metadata can be used both for local entities
 * (= the ones accessible as part of the deployed application using the SAML Extension) and remove entities (= the ones
 * user can interact with like IDPs).
 *
 * @author Vladimir Schaefer
 */
public class ExtendedMetadata implements Serializable, Cloneable {

    private boolean isLocal = false;
    private String alias;
    private String singingKey;
    private String encryptionKey;
    private boolean requireLogoutRequestSigned;
    private boolean requireLogoutResponseSigned;
    private boolean requireArtifactResolveSigned;

    /**
     * True in case entity is deployed locally.
     *
     * @return local flag
     */
    public boolean isLocal() {
        return isLocal;
    }

    /**
     * Flag indicates whether current entity is deployed locally or remotely. Local entities are the ones deployed as
     * part of the SAML Extension. Usually there is exactly one local entity.
     *
     * @param local local flag
     */
    public void setLocal(boolean local) {
        isLocal = local;
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
    public String getSingingKey() {
        return singingKey;
    }

    /**
     * Sets signing key to be used for interaction with the current entity. In case the entity is local the keyStore
     * must contain a private and public key with the given name. For remote entities only public key is required.
     * <p/>
     * Value can be used to override credential contained in the remote metadata.
     *
     * @param singingKey key for creation/verification of signatures
     */
    public void setSingingKey(String singingKey) {
        this.singingKey = singingKey;
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
