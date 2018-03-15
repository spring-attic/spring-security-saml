/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.opensaml.compat;

import java.security.interfaces.DSAParams;

import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;

/**
 * Interface for classes which store security-related configuration information, especially
 * related to the requirements for XML Signature and XML Encryption.
 */
public interface SecurityConfiguration {

    /**
     * Get the signature algorithm URI for the specified JCA key algorithm name.
     *
     * @param jcaAlgorithmName a JCA key algorithm name
     * @return a signature algorithm URI mapping, or null if no mapping is available
     */
    public String getSignatureAlgorithmURI(String jcaAlgorithmName);

    /**
     * Get the signature algorithm URI for the signing key contained within the specified credential.
     *
     * @param credential a credential containing a signing key
     * @return a signature algorithm URI mapping, or null if no mapping is available
     */
    public String getSignatureAlgorithmURI(Credential credential);

    /**
     * Get a digest method algorithm URI suitable for use as a Signature Reference DigestMethod value.
     *
     * @return a digest method algorithm URI
     */
    public String getSignatureReferenceDigestMethod();

    /**
     * Get a canonicalization algorithm URI suitable for use as a Signature CanonicalizationMethod value.
     *
     * @return a canonicalization algorithm URI
     */
    public String getSignatureCanonicalizationAlgorithm();

    /**
     * Get the value to be used as the Signature SignatureMethod HMACOutputLength value, used
     * only when signing with an HMAC algorithm.  This value is optional when using HMAC.
     *
     * @return the configured HMAC output length value
     */
    public Integer getSignatureHMACOutputLength();

    /**
     * Get the encryption algorithm URI for the specified JCA key algorithm name and optional key
     * length.
     *
     * Passing <code>null</code> as the key length will return the default algorithm URI for the specified
     * JCA algorithm, if a default is configured.  If no mapping for the specified key length is available,
     * the default mapping will be returned.
     *
     * @param jcaAlgorithmName a JCA key algorithm name
     * @param keyLength  optional key length parameter
     * @return an encryption algorithm URI, or null if no mapping is available
     */
    public String getDataEncryptionAlgorithmURI(String jcaAlgorithmName, Integer keyLength);

    /**
     * Get the encryption algorithm URI for the encryption key contained within the specified credential.
     *
     * @param credential a credential containing an encryption key
     * @return an encryption algorithm URI mapping, or null if no mapping is available
     */
    public String getDataEncryptionAlgorithmURI(Credential credential);

    /**
     * Get the key transport encryption algorithm URI for the specified JCA key algorithm name, optional key
     * length and optional JCA key algorithm name of the key to be encrypted.
     *
     * Note that typically the key length parameter is required for lookup of symmetric key wrap algorithm
     * URI's, but is typically not required or relevant for asymmetric key transport algorithms.
     *
     * If a mapping is not available considering the optional key length and wrapped algorithm parameters as passed,
     * a lookup will next be attempted by omiting the (non-null) wrapped key algorithm, and if that is unsuccessful,
     * by then omitting the (non-null) key length parameter.  If a mapping has still not been found, then a final
     * lookup attempt will be made using the key encryption key's JCA algorithm name alone.
     *
     * @param jcaAlgorithmName a JCA key algorithm name for the key encryption key
     * @param keyLength  optional key length parameter
     * @param wrappedKeyAlgorithm a JCA key algorithm name for the key to be encrypted
     * @return an encryption algorithm URI, or null if no mapping is available
     */
    public String getKeyTransportEncryptionAlgorithmURI(String jcaAlgorithmName, Integer keyLength,
                                                        String wrappedKeyAlgorithm);

    /**
     * Get the key transport encryption algorithm URI for the encryption key contained within the specified credential.
     *
     * @param credential a credential containing an encryption key
     * @param wrappedKeyAlgorithm the JCA key algorithm name of the key being encrypted
     * @return an encryption algorithm URI mapping, or null if no mapping is available
     */
    public String getKeyTransportEncryptionAlgorithmURI(Credential credential, String wrappedKeyAlgorithm);

    /**
     * Get the encryption algorithm URI to be used when auto-generating random data encryption keys.
     *
     * @return an encryption algorithm URI, or null if no default is available
     */
    public String getAutoGeneratedDataEncryptionKeyAlgorithmURI();

    /**
     * Get a DSA parameters instance which defines the default DSA key information to be used
     * within a DSA "key family".
     *
     * @param keyLength length of the DSA key whose parameters are desired
     * @return the default DSA parameters instance, or null if no default is available
     */
    public DSAParams getDSAParams(int keyLength);

    /**
     * Get the manager for named KeyInfoGenerator instances.
     *
     * @return the KeyInfoGenerator manager, or null if none is configured
     */
    public NamedKeyInfoGeneratorManager getKeyInfoGeneratorManager();

    /**
     * Get the KeyInfoCredentialResolver associated with the named configuration.
     *
     * @param name the name of the resolver configuration to return
     * @return a KeyInfoCredentialResolver instance
     */
    public KeyInfoCredentialResolver getKeyInfoCredentialResolver(String name);

    /**
     * Get the default KeyInfoCredentialResolver configuration.
     *
     * @return the default KeyInfoCredentialResolver
     */
    public KeyInfoCredentialResolver getDefaultKeyInfoCredentialResolver();

}