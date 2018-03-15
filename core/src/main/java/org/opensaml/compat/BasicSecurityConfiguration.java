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

import java.security.Key;
import java.security.interfaces.DSAParams;
import java.util.HashMap;
import java.util.Map;

import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Basic in-memory implementation of {@link SecurityConfiguration}.
 */
public class BasicSecurityConfiguration implements SecurityConfiguration {

    /** The name of the KeyInfoCredentialResolver default config. */
    public static final String KEYINFO_RESOLVER_DEFAULT_CONFIG = "_KEYINFO_RESOLVER_DEFAULT_";

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(BasicSecurityConfiguration.class);

    /** JCA key algorithm to signature URI mappings. */
    private Map<String, String> signatureAlgorithms;

    /** Signature canonicalization algorithm URI. */
    private String signatureCanonicalization;

    /** Signature Reference digest method algorithm URI. */
    private String signatureReferenceDigestMethod;

    /** Signature HMAC output length. */
    private Integer signatureHMACOutputLength;

    /** JCA key algorithm to data encryption URI mappings. */
    private Map<DataEncryptionIndex, String> dataEncryptionAlgorithms;

    /** JCA key algorithm to key transport encryption URI mappings. */
    private Map<KeyTransportEncryptionIndex, String> keyTransportEncryptionAlgorithms;

    /** Encryption algorithm URI for auto-generated data encryption keys. */
    private String autoGenEncryptionURI;

    /** Manager for named KeyInfoGenerator instances. */
    private NamedKeyInfoGeneratorManager keyInfoGeneratorManager;

    /** Set of named KeyInfoCredentialResolvers. */
    private Map<String, KeyInfoCredentialResolver> keyInfoCredentialResolvers;

    /** Default DSA key family parameters. */
    private Map<Integer, DSAParams> dsaParams;

    /** Constructor. */
    public BasicSecurityConfiguration() {
        signatureAlgorithms = new HashMap<String, String>();
        dataEncryptionAlgorithms = new HashMap<DataEncryptionIndex, String>();
        keyTransportEncryptionAlgorithms = new HashMap<KeyTransportEncryptionIndex, String>();
        keyInfoCredentialResolvers = new HashMap<String, KeyInfoCredentialResolver>();
        dsaParams = new HashMap<Integer, DSAParams>();
    }

    // Signature-related config

    /** {@inheritDoc} */
    public String getSignatureAlgorithmURI(String jcaAlgorithmName) {
        return signatureAlgorithms.get(jcaAlgorithmName);
    }

    /** {@inheritDoc} */
    public String getSignatureAlgorithmURI(Credential credential) {
        Key key = SecurityHelper.extractSigningKey(credential);
        if (key == null) {
            log.debug("Could not extract signing key from credential, unable to map to algorithm URI");
            return null;
        } else if (key.getAlgorithm() == null) {
            log.debug("Signing key algorithm value was not available, unable to map to algorithm URI");
            return null;
        }
        return getSignatureAlgorithmURI(key.getAlgorithm());
    }

    /**
     * Register a mapping from the specified JCA key algorithm name to a signature algorithm URI.
     *
     * @param jcaAlgorithmName the JCA key algorithm name to register
     * @param algorithmURI the algorithm URI to register
     */
    public void registerSignatureAlgorithmURI(String jcaAlgorithmName, String algorithmURI) {
        signatureAlgorithms.put(jcaAlgorithmName, algorithmURI);
    }

    /**
     * Deregister a mapping for the specified JCA key algorithm name.
     *
     * @param jcaAlgorithmName the JCA key algorithm name to deregister
     */
    public void deregisterSignatureAlgorithmURI(String jcaAlgorithmName) {
        signatureAlgorithms.remove(jcaAlgorithmName);
    }

    /** {@inheritDoc} */
    public String getSignatureCanonicalizationAlgorithm() {
        return signatureCanonicalization;
    }

    /**
     * Set a canonicalization algorithm URI suitable for use as a Signature CanonicalizationMethod value.
     *
     * @param algorithmURI a canonicalization algorithm URI
     */
    public void setSignatureCanonicalizationAlgorithm(String algorithmURI) {
        signatureCanonicalization = algorithmURI;
    }

    /** {@inheritDoc} */
    public String getSignatureReferenceDigestMethod() {
        return signatureReferenceDigestMethod;
    }

    /**
     * Set a digest method algorithm URI suitable for use as a Signature Reference DigestMethod value.
     *
     * @param algorithmURI a digest method algorithm URI
     */
    public void setSignatureReferenceDigestMethod(String algorithmURI) {
        signatureReferenceDigestMethod = algorithmURI;
    }

    /** {@inheritDoc} */
    public Integer getSignatureHMACOutputLength() {
        return signatureHMACOutputLength;
    }

    /**
     * Set the value to be used as the Signature SignatureMethod HMACOutputLength value, used
     * only when signing with an HMAC algorithm.  This value is optional when using HMAC.
     *
     * @param length the HMAC output length value to use when performing HMAC signing (may be null)
     */
    public void setSignatureHMACOutputLength(Integer length) {
        signatureHMACOutputLength = length;
    }

    //  Encryption-related config

    /** {@inheritDoc} */
    public String getDataEncryptionAlgorithmURI(String jcaAlgorithmName, Integer keyLength) {
        DataEncryptionIndex index = new DataEncryptionIndex(jcaAlgorithmName, keyLength);
        String algorithmURI = dataEncryptionAlgorithms.get(index);
        if (algorithmURI != null) {
            return algorithmURI;
        }
        if (keyLength != null) {
            // Fall through to default, i.e. with no specific key length registered
            log.debug("No data encryption algorithm mapping available for JCA name + key length, "
                          + "trying JCA name alone");
            index = new DataEncryptionIndex(jcaAlgorithmName, null);
            return dataEncryptionAlgorithms.get(index);
        }
        return null;
    }

    /** {@inheritDoc} */
    public String getDataEncryptionAlgorithmURI(Credential credential) {
        Key key = SecurityHelper.extractEncryptionKey(credential);
        if (key == null) {
            log.debug("Could not extract data encryption key from credential, unable to map to algorithm URI");
            return null;
        } else if (key.getAlgorithm() == null){
            log.debug("Data encryption key algorithm value was not available, unable to map to algorithm URI");
            return null;
        }
        Integer length = SecurityHelper.getKeyLength(key);
        return getDataEncryptionAlgorithmURI(key.getAlgorithm(), length);
    }

    /**
     * Register a mapping from the specified JCA algorithm name to an encryption algorithm URI.
     *
     * @param jcaAlgorithmName the JCA algorithm name to register
     * @param keyLength the key length to register (may be null)
     * @param algorithmURI the algorithm URI to register
     */
    public void registerDataEncryptionAlgorithmURI(String jcaAlgorithmName, Integer keyLength, String algorithmURI) {
        DataEncryptionIndex index = new DataEncryptionIndex(jcaAlgorithmName, keyLength);
        dataEncryptionAlgorithms.put(index, algorithmURI);
    }

    /**
     * Deregister a mapping for the specified JCA algorithm name.
     *
     * @param jcaAlgorithmName the JCA algorithm name to deregister
     * @param keyLength the key length to deregister (may be null)
     */
    public void deregisterDataEncryptionAlgorithmURI(String jcaAlgorithmName, Integer keyLength) {
        DataEncryptionIndex index = new DataEncryptionIndex(jcaAlgorithmName, keyLength);
        dataEncryptionAlgorithms.remove(index);
    }

    /** {@inheritDoc} */
    public String getKeyTransportEncryptionAlgorithmURI(String jcaAlgorithmName, Integer keyLength,
                                                        String wrappedKeyAlgorithm) {

        KeyTransportEncryptionIndex index =
            new KeyTransportEncryptionIndex(jcaAlgorithmName, keyLength, wrappedKeyAlgorithm);
        String algorithmURI = keyTransportEncryptionAlgorithms.get(index);
        if (algorithmURI != null) {
            return algorithmURI;
        }

        if (wrappedKeyAlgorithm != null) {
            // Fall through to case of no specific wrapped key algorithm registered
            log.debug("No data encryption algorithm mapping available for JCA name + key length + wrapped algorithm, "
                          + "trying JCA name + key length");
            index = new KeyTransportEncryptionIndex(jcaAlgorithmName, keyLength, null);
            algorithmURI = keyTransportEncryptionAlgorithms.get(index);
            if (algorithmURI != null) {
                return algorithmURI;
            }
        }
        if (keyLength != null) {
            // Fall through to case of no specific key length registered
            log.debug("No data encryption algorithm mapping available for JCA name + key length + wrapped algorithm, "
                          + "trying JCA name + wrapped algorithm");
            index = new KeyTransportEncryptionIndex(jcaAlgorithmName, null, wrappedKeyAlgorithm);
            algorithmURI = keyTransportEncryptionAlgorithms.get(index);
            if (algorithmURI != null) {
                return algorithmURI;
            }
        }
        // Fall through to case of no specific key length or wrapped key algorithm registered
        log.debug("No data encryption algorithm mapping available for JCA name + key length + wrapped algorithm, "
                      + "trying JCA name alone");
        index = new KeyTransportEncryptionIndex(jcaAlgorithmName, null, null);
        return keyTransportEncryptionAlgorithms.get(index);
    }

    /** {@inheritDoc} */
    public String getKeyTransportEncryptionAlgorithmURI(Credential credential, String wrappedKeyAlgorithm) {
        Key key = SecurityHelper.extractEncryptionKey(credential);
        if (key == null) {
            log.debug("Could not extract key transport encryption key from credential, unable to map to algorithm URI");
            return null;
        } else if (key.getAlgorithm() == null){
            log.debug("Key transport encryption key algorithm value was not available, unable to map to algorithm URI");
            return null;
        }
        Integer length = SecurityHelper.getKeyLength(key);
        return getKeyTransportEncryptionAlgorithmURI(key.getAlgorithm(), length, wrappedKeyAlgorithm);
    }

    /**
     * Register a mapping from the specified JCA algorithm name to an encryption algorithm URI.
     *
     * @param jcaAlgorithmName the JCA algorithm name to register
     * @param keyLength the key length to register (may be null)
     * @param wrappedKeyAlgorithm the JCA algorithm name of the key to be encrypted (may be null)
     * @param algorithmURI the algorithm URI to register
     */
    public void registerKeyTransportEncryptionAlgorithmURI(String jcaAlgorithmName, Integer keyLength,
                                                           String wrappedKeyAlgorithm, String algorithmURI) {

        KeyTransportEncryptionIndex index =
            new KeyTransportEncryptionIndex(jcaAlgorithmName, keyLength, wrappedKeyAlgorithm);
        keyTransportEncryptionAlgorithms.put(index, algorithmURI);
    }

    /**
     * Deregister a mapping for the specified JCA algorithm name.
     *
     * @param jcaAlgorithmName the JCA algorithm name to deregister
     * @param keyLength the key length to deregister (may be null)
     * @param wrappedKeyAlgorithm the JCA algorithm name of the key to be encrypted (may be null)
     */
    public void deregisterKeyTransportEncryptionAlgorithmURI(String jcaAlgorithmName, Integer keyLength,
                                                             String wrappedKeyAlgorithm) {

        KeyTransportEncryptionIndex index =
            new KeyTransportEncryptionIndex(jcaAlgorithmName, keyLength, wrappedKeyAlgorithm);
        keyTransportEncryptionAlgorithms.remove(index);

    }

    /** {@inheritDoc} */
    public String getAutoGeneratedDataEncryptionKeyAlgorithmURI() {
        return autoGenEncryptionURI;
    }

    /**
     * Set the encryption algorithm URI to be used when auto-generating random data encryption keys.
     *
     * @param algorithmURI the encryption algorithm URI to use
     */
    public void setAutoGeneratedDataEncryptionKeyAlgorithmURI(String algorithmURI) {
        autoGenEncryptionURI = algorithmURI;
    }


    // KeyInfo-related config

    /** {@inheritDoc} */
    public NamedKeyInfoGeneratorManager getKeyInfoGeneratorManager() {
        return keyInfoGeneratorManager;
    }
    /**
     * Set the manager for named KeyInfoGenerator instances.
     *
     * @param keyInfoManager the KeyInfoGenerator manager to use
     */
    public void setKeyInfoGeneratorManager(NamedKeyInfoGeneratorManager keyInfoManager) {
        keyInfoGeneratorManager = keyInfoManager;
    }

    /** {@inheritDoc} */
    public KeyInfoCredentialResolver getDefaultKeyInfoCredentialResolver() {
        return keyInfoCredentialResolvers.get(KEYINFO_RESOLVER_DEFAULT_CONFIG);
    }

    /**
     * Set the default KeyInfoCredentialResolver config.
     *
     * @param resolver the default KeyInfoCredentialResolver
     */
    public void setDefaultKeyInfoCredentialResolver(KeyInfoCredentialResolver resolver) {
        keyInfoCredentialResolvers.put(KEYINFO_RESOLVER_DEFAULT_CONFIG, resolver);
    }

    /** {@inheritDoc} */
    public KeyInfoCredentialResolver getKeyInfoCredentialResolver(String name) {
        return keyInfoCredentialResolvers.get(name);
    }

    /**
     * Register a named KeyInfoCredentialResolver configuration.
     *
     * @param name the name of the configuration
     * @param resolver the KeyInfoCredentialResolver to register
     */
    public void registerKeyInfoCredentialResolver(String name, KeyInfoCredentialResolver resolver) {
        keyInfoCredentialResolvers.put(name, resolver);
    }

    /**
     * Deregister a named KeyInfoCredentialResolver configuration.
     *
     * @param name the name of the configuration
     */
    public void deregisterKeyInfoCredentialResolver(String name) {
        keyInfoCredentialResolvers.remove(name);
    }

    // Miscellaneous config

    /** {@inheritDoc} */
    public DSAParams getDSAParams(int keyLength) {
        return dsaParams.get(keyLength);
    }

    /**
     * Set a DSA parameters instance which defines the default DSA key information to be used
     * within a DSA "key family".
     *
     * @param keyLength the key length of the DSA parameters
     * @param params the default DSA parameters instance
     */
    public void setDSAParams(int keyLength, DSAParams params) {
        dsaParams.put(keyLength, params);
    }


    /**
     * Class used as an index to the data encryption algorithm URI map.
     */
    protected class DataEncryptionIndex {

        /** The JCA key algorithm name. */
        private String keyAlgorithm;

        /** The key length.  Optional, may be null. */
        private Integer keyLength;

        /**
         * Constructor.
         *
         * @param jcaAlgorithmName the JCA algorithm name
         * @param length the key length (optional, may be null)
         */
        protected DataEncryptionIndex(String jcaAlgorithmName, Integer length) {
            if (DataTypeHelper.isEmpty(jcaAlgorithmName)) {
                throw new IllegalArgumentException("JCA Algorithm name may not be null or empty");
            }
            keyAlgorithm = DataTypeHelper.safeTrimOrNullString(jcaAlgorithmName);
            keyLength = length;
        }

        /** {@inheritDoc} */
        public boolean equals(Object obj) {
            if(obj == this){
                return true;
            }

            if (! (obj instanceof DataEncryptionIndex)) {
                return false;
            }
            DataEncryptionIndex other = (DataEncryptionIndex) obj;

            if (! this.keyAlgorithm.equals(other.keyAlgorithm)) {
                return false;
            }
            if (this.keyLength == null) {
                return other.keyLength == null;
            } else {
                return this.keyLength.equals(other.keyLength);
            }

        }

        /** {@inheritDoc} */
        public int hashCode() {
            int result = 17;
            result = 37*result + keyAlgorithm.hashCode();
            if (keyLength != null) {
                result = 37*result + keyLength.hashCode();
            }
            return result;
        }

        /** {@inheritDoc} */
        public String toString() {
            return String.format("[%s,%s]", keyAlgorithm, keyLength);
        }

    }

    /**
     * Class used as an index to the key transport encryption algorithm URI map.
     */
    protected class KeyTransportEncryptionIndex {

        /** The JCA key algorithm name. */
        private String keyAlgorithm;

        /** The key length.  Optional, may be null. */
        private Integer keyLength;

        /** The JCA key algorithm name of the key to be encrypted. */
        private String wrappedAlgorithm;

        /**
         * Constructor.
         *
         * @param jcaAlgorithmName the JCA algorithm name
         * @param length the key length (optional, may be null)
         * @param wrappedKeyAlgorithm the JCA algorithm name of the key to be encrypted (optional, may be null)
         */
        protected KeyTransportEncryptionIndex(String jcaAlgorithmName, Integer length, String wrappedKeyAlgorithm) {
            if (DataTypeHelper.isEmpty(jcaAlgorithmName)) {
                throw new IllegalArgumentException("JCA Algorithm name may not be null or empty");
            }
            keyAlgorithm = DataTypeHelper.safeTrimOrNullString(jcaAlgorithmName);
            keyLength = length;
            wrappedAlgorithm = DataTypeHelper.safeTrimOrNullString(wrappedKeyAlgorithm);
        }

        /** {@inheritDoc} */
        public boolean equals(Object obj) {
            if(obj == this){
                return true;
            }

            if (! (obj instanceof KeyTransportEncryptionIndex)) {
                return false;
            }
            KeyTransportEncryptionIndex other = (KeyTransportEncryptionIndex) obj;

            if (! this.keyAlgorithm.equals(other.keyAlgorithm)) {
                return false;
            }
            if (this.keyLength == null) {
                if (other.keyLength != null) {
                    return false;
                }
            } else {
                if (! this.keyLength.equals(other.keyLength)) {
                    return false;
                }
            }
            if (this.wrappedAlgorithm == null) {
                return other.wrappedAlgorithm == null;
            } else {
                return this.wrappedAlgorithm.equals(other.wrappedAlgorithm);
            }
        }

        /** {@inheritDoc} */
        public int hashCode() {
            int result = 17;
            result = 37*result + keyAlgorithm.hashCode();
            if (keyLength != null) {
                result = 37*result + keyLength.hashCode();
            }
            if (wrappedAlgorithm != null) {
                result = 37*result + wrappedAlgorithm.hashCode();
            }
            return result;
        }

        /** {@inheritDoc} */
        public String toString() {
            return String.format("[%s,%s,%s]", keyAlgorithm, keyLength, wrappedAlgorithm);
        }

    }
}
