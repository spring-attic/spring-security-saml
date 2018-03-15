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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;

import net.shibboleth.utilities.java.support.collection.LazySet;
import org.apache.commons.ssl.PKCS8Key;
import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.JCEMapper;
import org.opensaml.core.config.Configuration;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.crypto.SigningUtil;
import org.opensaml.security.x509.BasicX509Credential;

import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.codec.Base64;

/**
 * Helper methods for security-related requirements.
 */
public final class SecurityHelper {

    /** Additional algorithm URI's which imply RSA keys. */
    private static Set<String> rsaAlgorithmURIs;

    /** Additional algorithm URI's which imply DSA keys. */
    private static Set<String> dsaAlgorithmURIs;

    /** Additional algorithm URI's which imply ECDSA keys. */
    private static Set<String> ecdsaAlgorithmURIs;

    /** Constructor. */
    private SecurityHelper() {
    }

    /**
     * Get the Java security JCA/JCE algorithm identifier associated with an algorithm URI.
     *
     * @param algorithmURI the algorithm URI to evaluate
     * @return the Java algorithm identifier, or null if the mapping is unavailable or indeterminable from the URI
     */
    public static String getAlgorithmIDFromURI(String algorithmURI) {
        return DataTypeHelper.safeTrimOrNullString(JCEMapper.translateURItoJCEID(algorithmURI));
    }

    /**
     * Check whether the signature method algorithm URI indicates HMAC.
     *
     * @param signatureAlgorithm the signature method algorithm URI
     * @return true if URI indicates HMAC, false otherwise
     */
    public static boolean isHMAC(String signatureAlgorithm) {
        String algoClass = DataTypeHelper.safeTrimOrNullString(JCEMapper.getAlgorithmClassFromURI(signatureAlgorithm));
        return ApacheXMLSecurityConstants.ALGO_CLASS_MAC.equals(algoClass);
    }

    /**
     * Get the Java security JCA/JCE key algorithm specifier associated with an algorithm URI.
     *
     * @param algorithmURI the algorithm URI to evaluate
     * @return the Java key algorithm specifier, or null if the mapping is unavailable or indeterminable from the URI
     */
    public static String getKeyAlgorithmFromURI(String algorithmURI) {
        // The default Apache config file currently only includes the key algorithm for
        // the block ciphers and key wrap URI's. Note: could use a custom config file which contains others.
        String apacheValue = DataTypeHelper.safeTrimOrNullString(JCEMapper.getJCEKeyAlgorithmFromURI(algorithmURI));
        if (apacheValue != null) {
            return apacheValue;
        }

        // HMAC uses any symmetric key, so there is no implied specific key algorithm
        if (isHMAC(algorithmURI)) {
            return null;
        }

        // As a last ditch fallback, check some known common and supported ones.
        if (rsaAlgorithmURIs.contains(algorithmURI)) {
            return "RSA";
        }
        if (dsaAlgorithmURIs.contains(algorithmURI)) {
            return "DSA";
        }
        if (ecdsaAlgorithmURIs.contains(algorithmURI)) {
            return "EC";
        }

        return null;
    }

    /**
     * Get the length of the key indicated by the algorithm URI, if applicable and available.
     *
     * @param algorithmURI the algorithm URI to evaluate
     * @return the length of the key indicated by the algorithm URI, or null if the length is either unavailable or
     *         indeterminable from the URI
     */
    public static Integer getKeyLengthFromURI(String algorithmURI) {
        Logger log = getLogger();
        String algoClass = DataTypeHelper.safeTrimOrNullString(JCEMapper.getAlgorithmClassFromURI(algorithmURI));

        if (ApacheXMLSecurityConstants.ALGO_CLASS_BLOCK_ENCRYPTION.equals(algoClass)
            || ApacheXMLSecurityConstants.ALGO_CLASS_SYMMETRIC_KEY_WRAP.equals(algoClass)) {

            try {
                int keyLength = JCEMapper.getKeyLengthFromURI(algorithmURI);
                return new Integer(keyLength);
            } catch (NumberFormatException e) {
                log.warn("XML Security config contained invalid key length value for algorithm URI: " + algorithmURI);
            }
        }

        log.info("Mapping from algorithm URI {} to key length not available", algorithmURI);
        return null;
    }

    /**
     * Generates a random Java JCE symmetric Key object from the specified XML Encryption algorithm URI.
     *
     * @param algoURI The XML Encryption algorithm URI
     * @return a randomly-generated symmetric Key
     * @throws NoSuchAlgorithmException thrown if the specified algorithm is invalid
     * @throws KeyException thrown if the length of the key to generate could not be determined
     */
    public static SecretKey generateSymmetricKey(String algoURI) throws NoSuchAlgorithmException, KeyException {
        Logger log = getLogger();
        String jceAlgorithmName = getKeyAlgorithmFromURI(algoURI);
        if (DataTypeHelper.isEmpty(jceAlgorithmName)) {
            log.error("Mapping from algorithm URI '" + algoURI
                          + "' to key algorithm not available, key generation failed");
            throw new NoSuchAlgorithmException("Algorithm URI'" + algoURI + "' is invalid for key generation");
        }

        Integer keyLength = null;
        if (EncryptionConstants.ALGO_ID_BLOCKCIPHER_TRIPLEDES.equals(algoURI)
            || EncryptionConstants.ALGO_ID_KEYWRAP_TRIPLEDES.equals(algoURI)) {
            // We have to special case this b/c a 3DES key is 192 bits, but with KeyGenerator the JCA providers
            // inconsistently allow either 112/168 (SunJCE) or 112/168/192 (BC). Per JCA docs they're all
            // required to support 168. We don't do this in getKeyLength() b/c the 3DES key actually is 192 bits.
            keyLength = 168;
        } else {
            keyLength = getKeyLengthFromURI(algoURI);
        }

        if (keyLength == null) {
            log.error("Key length could not be determined from algorithm URI, can't generate key");
            throw new KeyException("Key length not determinable from algorithm URI, could not generate new key");
        }
        KeyGenerator keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
        keyGenerator.init(keyLength);
        return keyGenerator.generateKey();
    }

    /**
     * Extract the encryption key from the credential.
     *
     * @param credential the credential containing the encryption key
     * @return the encryption key (either a public key or a secret (symmetric) key
     */
    public static Key extractEncryptionKey(Credential credential) {
        if (credential == null) {
            return null;
        }
        if (credential.getPublicKey() != null) {
            return credential.getPublicKey();
        } else {
            return credential.getSecretKey();
        }
    }

    /**
     * Extract the decryption key from the credential.
     *
     * @param credential the credential containing the decryption key
     * @return the decryption key (either a private key or a secret (symmetric) key
     */
    public static Key extractDecryptionKey(Credential credential) {
        if (credential == null) {
            return null;
        }
        if (credential.getPrivateKey() != null) {
            return credential.getPrivateKey();
        } else {
            return credential.getSecretKey();
        }
    }

    /**
     * Extract the signing key from the credential.
     *
     * @param credential the credential containing the signing key
     * @return the signing key (either a private key or a secret (symmetric) key
     */
    public static Key extractSigningKey(Credential credential) {
        if (credential == null) {
            return null;
        }
        if (credential.getPrivateKey() != null) {
            return credential.getPrivateKey();
        } else {
            return credential.getSecretKey();
        }
    }

    /**
     * Extract the verification key from the credential.
     *
     * @param credential the credential containing the verification key
     * @return the verification key (either a public key or a secret (symmetric) key
     */
    public static Key extractVerificationKey(Credential credential) {
        if (credential == null) {
            return null;
        }
        if (credential.getPublicKey() != null) {
            return credential.getPublicKey();
        } else {
            return credential.getSecretKey();
        }
    }

    /**
     * Get the key length in bits of the specified key.
     *
     * @param key the key to evaluate
     * @return length of the key in bits, or null if the length can not be determined
     */
    public static Integer getKeyLength(Key key) {
        Logger log = getLogger();
        // TODO investigate techniques (and use cases) to determine length in other cases,
        // e.g. RSA and DSA keys, and non-RAW format symmetric keys
        if (key instanceof SecretKey && "RAW".equals(key.getFormat())) {
            return key.getEncoded().length * 8;
        }
        log.debug("Unable to determine length in bits of specified Key instance");
        return null;
    }

    /**
     * Get a simple, minimal credential containing a secret (symmetric) key.
     *
     * @param secretKey the symmetric key to wrap
     * @return a credential containing the secret key specified
     */
    public static BasicCredential getSimpleCredential(SecretKey secretKey) {
        if (secretKey == null) {
            throw new IllegalArgumentException("A secret key is required");
        }
        BasicCredential cred = new BasicCredential() {};
        cred.setSecretKey(secretKey);
        return cred;
    }

    /**
     * Get a simple, minimal credential containing a public key, and optionally a private key.
     *
     * @param publicKey the public key to wrap
     * @param privateKey the private key to wrap, which may be null
     * @return a credential containing the key(s) specified
     */
    public static BasicCredential getSimpleCredential(PublicKey publicKey, PrivateKey privateKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("A public key is required");
        }
        BasicCredential cred = new BasicCredential(){};
        cred.setPublicKey(publicKey);
        cred.setPrivateKey(privateKey);
        return cred;
    }

    /**
     * Get a simple, minimal credential containing an end-entity X.509 certificate, and optionally a private key.
     *
     * @param cert the end-entity certificate to wrap
     * @param privateKey the private key to wrap, which may be null
     * @return a credential containing the certificate and key specified
     */
    public static BasicX509Credential getSimpleCredential(X509Certificate cert, PrivateKey privateKey) {
        if (cert == null) {
            throw new IllegalArgumentException("A certificate is required");
        }
        BasicX509Credential cred = new BasicX509Credential(cert, privateKey);
        return cred;
    }

    /**
     * Decodes secret keys in DER and PEM format.
     *
     * This method is not yet implemented.
     *
     * @param key secret key
     * @param password password if the key is encrypted or null if not
     *
     * @return the decoded key
     *
     * @throws KeyException thrown if the key can not be decoded
     */
    public static SecretKey decodeSecretKey(byte[] key, char[] password) throws KeyException {
        // TODO
        throw new UnsupportedOperationException("This method is not yet supported");
    }

    /**
     * Decodes RSA/DSA public keys in DER-encoded "SubjectPublicKeyInfo" format.
     *
     * @param key encoded key
     * @param password password if the key is encrypted or null if not
     *
     * @return decoded key
     *
     * @throws KeyException thrown if the key can not be decoded
     */
    public static PublicKey decodePublicKey(byte[] key, char[] password) throws KeyException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
        try {
            return buildKey(keySpec, "RSA");
        } catch (KeyException ex) {
        }
        try {
            return buildKey(keySpec, "DSA");
        } catch (KeyException ex) {
        }
        try {
            return buildKey(keySpec, "EC");
        } catch (KeyException ex) {
        }
        throw new KeyException("Unsupported key type.");
    }

    /**
     * Derives the public key from either a DSA or RSA private key.
     *
     * @param key the private key to derive the public key from
     *
     * @return the derived public key
     *
     * @throws KeyException thrown if the given private key is not a DSA or RSA key or there is a problem generating the
     *             public key
     */
    public static PublicKey derivePublicKey(PrivateKey key) throws KeyException {
        KeyFactory factory;
        if (key instanceof DSAPrivateKey) {
            DSAPrivateKey dsaKey = (DSAPrivateKey) key;
            DSAParams keyParams = dsaKey.getParams();
            BigInteger y = keyParams.getG().modPow(dsaKey.getX(), keyParams.getP());
            DSAPublicKeySpec pubKeySpec = new DSAPublicKeySpec(y, keyParams.getP(), keyParams.getQ(), keyParams.getG());

            try {
                factory = KeyFactory.getInstance("DSA");
                return factory.generatePublic(pubKeySpec);
            } catch (GeneralSecurityException e) {
                throw new KeyException("Unable to derive public key from DSA private key", e);
            }
        } else if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;
            RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(rsaKey.getModulus(), rsaKey.getPublicExponent());

            try {
                factory = KeyFactory.getInstance("RSA");
                return factory.generatePublic(pubKeySpec);
            } catch (GeneralSecurityException e) {
                throw new KeyException("Unable to derive public key from RSA private key", e);
            }
        } else {
            throw new KeyException("Private key was not a DSA or RSA key");
        }
    }

    /**
     * Decodes RSA/DSA private keys in DER, PEM, or PKCS#8 (encrypted or unencrypted) formats.
     *
     * @param key encoded key
     * @param password decryption password or null if the key is not encrypted
     *
     * @return deocded private key
     *
     * @throws KeyException thrown if the key can not be decoded
     */
    public static PrivateKey decodePrivateKey(File key, char[] password) throws KeyException {
        if (!key.exists()) {
            throw new KeyException("Key file " + key.getAbsolutePath() + " does not exist");
        }

        if (!key.canRead()) {
            throw new KeyException("Key file " + key.getAbsolutePath() + " is not readable");
        }

        try {
            return decodePrivateKey(DataTypeHelper.fileToByteArray(key), password);
        } catch (IOException e) {
            throw new KeyException("Error reading Key file " + key.getAbsolutePath(), e);
        }
    }

    /**
     * Decodes RSA/DSA private keys in DER, PEM, or PKCS#8 (encrypted or unencrypted) formats.
     *
     * @param key encoded key
     * @param password decryption password or null if the key is not encrypted
     *
     * @return deocded private key
     *
     * @throws KeyException thrown if the key can not be decoded
     */
    public static PrivateKey decodePrivateKey(byte[] key, char[] password) throws KeyException {
        try {
            PKCS8Key deocodedKey = new PKCS8Key(key, password);
            return deocodedKey.getPrivateKey();
        } catch (GeneralSecurityException e) {
            throw new KeyException("Unable to decode private key", e);
        }
    }

    /**
     * Build Java certificate from base64 encoding.
     *
     * @param base64Cert base64-encoded certificate
     * @return a native Java X509 certificate
     * @throws CertificateException thrown if there is an error constructing certificate
     */
    public static java.security.cert.X509Certificate buildJavaX509Cert(String base64Cert) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream input = new ByteArrayInputStream(Base64.decode(base64Cert.getBytes()));
        return (java.security.cert.X509Certificate) cf.generateCertificate(input);
    }

    /**
     * Build Java CRL from base64 encoding.
     *
     * @param base64CRL base64-encoded CRL
     * @return a native Java X509 CRL
     * @throws CertificateException thrown if there is an error constructing certificate
     * @throws CRLException  thrown if there is an error constructing CRL
     */
    public static java.security.cert.X509CRL buildJavaX509CRL(String base64CRL)
        throws CertificateException, CRLException {
        CertificateFactory  cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream input = new ByteArrayInputStream(Base64.decode(base64CRL.getBytes()));
        return (java.security.cert.X509CRL) cf.generateCRL(input);
    }

    /**
     * Build Java DSA public key from base64 encoding.
     *
     * @param base64EncodedKey base64-encoded DSA public key
     * @return a native Java DSAPublicKey
     * @throws KeyException thrown if there is an error constructing key
     */
    public static DSAPublicKey buildJavaDSAPublicKey(String base64EncodedKey) throws KeyException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(base64EncodedKey.getBytes()));
        return (DSAPublicKey) buildKey(keySpec, "DSA");
    }

    /**
     * Build Java RSA public key from base64 encoding.
     *
     * @param base64EncodedKey base64-encoded RSA public key
     * @return a native Java RSAPublicKey
     * @throws KeyException thrown if there is an error constructing key
     */
    public static RSAPublicKey buildJavaRSAPublicKey(String base64EncodedKey) throws KeyException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(base64EncodedKey.getBytes()));
        return (RSAPublicKey) buildKey(keySpec, "RSA");
    }

    /**
     * Build Java EC public key from base64 encoding.
     *
     * @param base64EncodedKey base64-encoded EC public key
     * @return a native Java ECPublicKey
     * @throws KeyException thrown if there is an error constructing key
     */
    public static ECPublicKey buildJavaECPublicKey(String base64EncodedKey) throws KeyException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(base64EncodedKey.getBytes()));
        return (ECPublicKey) buildKey(keySpec, "EC");
    }

    /**
     * Build Java RSA private key from base64 encoding.
     *
     * @param base64EncodedKey base64-encoded RSA private key
     * @return a native Java RSAPrivateKey
     * @throws KeyException thrown if there is an error constructing key
     */
    public static RSAPrivateKey buildJavaRSAPrivateKey(String base64EncodedKey) throws KeyException {
        PrivateKey key =  buildJavaPrivateKey(base64EncodedKey);
        if (! (key instanceof RSAPrivateKey)) {
            throw new KeyException("Generated key was not an RSAPrivateKey instance");
        }
        return (RSAPrivateKey) key;
    }

    /**
     * Build Java DSA private key from base64 encoding.
     *
     * @param base64EncodedKey base64-encoded DSA private key
     * @return a native Java DSAPrivateKey
     * @throws KeyException thrown if there is an error constructing key
     */
    public static DSAPrivateKey buildJavaDSAPrivateKey(String base64EncodedKey)  throws KeyException {
        PrivateKey key =  buildJavaPrivateKey(base64EncodedKey);
        if (! (key instanceof DSAPrivateKey)) {
            throw new KeyException("Generated key was not a DSAPrivateKey instance");
        }
        return (DSAPrivateKey) key;
    }

    /**
     * Build Java EC private key from base64 encoding.
     *
     * @param base64EncodedKey base64-encoded EC private key
     * @return a native Java ECPrivateKey
     * @throws KeyException thrown if there is an error constructing key
     */
    public static ECPrivateKey buildJavaECPrivateKey(String base64EncodedKey) throws KeyException {
        PrivateKey key =  buildJavaPrivateKey(base64EncodedKey);
        if (! (key instanceof ECPrivateKey)) {
            throw new KeyException("Generated key was not an ECPrivateKey instance");
        }
        return (ECPrivateKey) key;
    }

    /**
     * Build Java private key from base64 encoding. The key should have no password.
     *
     * @param base64EncodedKey base64-encoded private key
     * @return a native Java PrivateKey
     * @throws KeyException thrown if there is an error constructing key
     */
    public static PrivateKey buildJavaPrivateKey(String base64EncodedKey)  throws KeyException {
        return SecurityHelper.decodePrivateKey(Base64.decode(base64EncodedKey.getBytes()), null);
    }

    /**
     * Generates a public key from the given key spec.
     *
     * @param keySpec {@link KeySpec} specification for the key
     * @param keyAlgorithm key generation algorithm, only DSA and RSA supported
     *
     * @return the generated {@link PublicKey}
     *
     * @throws KeyException thrown if the key algorithm is not supported by the JCE or the key spec does not
     *             contain valid information
     */
    public static PublicKey buildKey(KeySpec keySpec, String keyAlgorithm) throws KeyException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException(keyAlgorithm + "algorithm is not supported by the JCE", e);
        } catch (InvalidKeySpecException e) {
            throw new KeyException("Invalid key information", e);
        }
    }

    /**
     * Randomly generates a Java JCE symmetric Key object from the specified XML Encryption algorithm URI.
     *
     * @param algoURI  The XML Encryption algorithm URI
     * @return a randomly-generated symmteric key
     * @throws NoSuchProviderException  provider not found
     * @throws NoSuchAlgorithmException algorithm not found
     */
    public static SecretKey generateKeyFromURI(String algoURI)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        String jceAlgorithmName = JCEMapper.getJCEKeyAlgorithmFromURI(algoURI);
        int keyLength = JCEMapper.getKeyLengthFromURI(algoURI);
        return generateKey(jceAlgorithmName, keyLength, null);
    }

    /**
     * Randomly generates a Java JCE KeyPair object from the specified XML Encryption algorithm URI.
     *
     * @param algoURI  The XML Encryption algorithm URI
     * @param keyLength  the length of key to generate
     * @return a randomly-generated KeyPair
     * @throws NoSuchProviderException  provider not found
     * @throws NoSuchAlgorithmException  algorithm not found
     */
    public static KeyPair generateKeyPairFromURI(String algoURI, int keyLength)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        String jceAlgorithmName = JCEMapper.getJCEKeyAlgorithmFromURI(algoURI);
        return generateKeyPair(jceAlgorithmName, keyLength, null);
    }

    /**
     * Generate a random symmetric key.
     *
     * @param algo key algorithm
     * @param keyLength key length
     * @param provider JCA provider
     * @return randomly generated symmetric key
     * @throws NoSuchAlgorithmException algorithm not found
     * @throws NoSuchProviderException provider not found
     */
    public static SecretKey generateKey(String algo, int keyLength, String provider)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        SecretKey key = null;
        KeyGenerator keyGenerator = null;
        if (provider != null) {
            keyGenerator = KeyGenerator.getInstance(algo, provider);
        } else {
            keyGenerator = KeyGenerator.getInstance(algo);
        }
        keyGenerator.init(keyLength);
        key = keyGenerator.generateKey();
        return key;
    }

    /**
     * Generate a random asymmetric key pair.
     *
     * @param algo key algorithm
     * @param keyLength key length
     * @param provider JCA provider
     * @return randomly generated key
     * @throws NoSuchAlgorithmException algorithm not found
     * @throws NoSuchProviderException provider not found
     */
    public static KeyPair generateKeyPair(String algo, int keyLength, String provider)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGenerator = null;
        if (provider != null) {
            keyGenerator = KeyPairGenerator.getInstance(algo, provider);
        } else {
            keyGenerator = KeyPairGenerator.getInstance(algo);
        }
        keyGenerator.initialize(keyLength);
        return keyGenerator.generateKeyPair();
    }

    /**
     * Generate a random symmetric key and return in a BasicCredential.
     *
     * @param algorithmURI The XML Encryption algorithm URI
     * @return a basic credential containing a randomly generated symmetric key
     * @throws NoSuchAlgorithmException algorithm not found
     * @throws NoSuchProviderException provider not found
     */
    public static Credential generateKeyAndCredential(String algorithmURI)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        SecretKey key = generateKeyFromURI(algorithmURI);
        BasicCredential credential = new BasicCredential(){};
        credential.setSecretKey(key);
        return credential;
    }

    /**
     * Generate a random asymmetric key pair and return in a BasicCredential.
     *
     * @param algorithmURI The XML Encryption algorithm URI
     * @param keyLength key length
     * @param includePrivate if true, the private key will be included as well
     * @return a basic credential containing a randomly generated asymmetric key pair
     * @throws NoSuchAlgorithmException algorithm not found
     * @throws NoSuchProviderException provider not found
     */
    public static Credential generateKeyPairAndCredential(String algorithmURI, int keyLength, boolean includePrivate)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair keyPair = generateKeyPairFromURI(algorithmURI, keyLength);
        BasicCredential credential = new BasicCredential(){};
        credential.setPublicKey(keyPair.getPublic());
        if (includePrivate) {
            credential.setPrivateKey(keyPair.getPrivate());
        }
        return credential;
    }


    /**
     * Compare the supplied public and private keys, and determine if they correspond to the same key pair.
     *
     * @param pubKey the public key
     * @param privKey the private key
     * @return true if the public and private are from the same key pair, false if not
     * @throws SecurityException if the keys can not be evaluated, or if the key algorithm is unsupported or unknown
     */
    public static boolean matchKeyPair(PublicKey pubKey, PrivateKey privKey) throws SecurityException  {
        Logger log = getLogger();
        // This approach attempts to match the keys by signing and then validating some known data.

        if (pubKey == null || privKey == null) {
            throw new SecurityException("Either public or private key was null");
        }

        // Need to dynamically determine the JCA signature algorithm ID to use from the key algorithm.
        // Don't currently have a direct mapping, so have to map to XML Signature algorithm URI first,
        // then map that to JCA algorithm ID.
        SecurityConfiguration secConfig = GlobalSecurityConfiguration.getGlobalSecurityConfiguration();
        if (secConfig == null) {
            throw new SecurityException("Global security configuration was null, could not resolve signing algorithm");
        }
        String algoURI = secConfig.getSignatureAlgorithmURI(privKey.getAlgorithm());
        if (algoURI == null) {
            throw new SecurityException("Can't determine algorithm URI from key algorithm: " + privKey.getAlgorithm());
        }
        String jcaAlgoID = getAlgorithmIDFromURI(algoURI);
        if (jcaAlgoID == null) {
            throw new SecurityException("Can't determine JCA algorithm ID from algorithm URI: " + algoURI);
        }

        if (log.isDebugEnabled()) {
            log.debug("Attempting to match key pair containing key algorithms public '{}' private '{}', "
                          + "using JCA signature algorithm '{}'", new Object[] { pubKey.getAlgorithm(),
                privKey.getAlgorithm(), jcaAlgoID, });
        }

        byte[] data = "This is the data to sign".getBytes();
        byte[] signature = SigningUtil.sign(privKey, jcaAlgoID, data);
        return SigningUtil.verify(pubKey, jcaAlgoID, signature, data);
    }

    /**
     * Prepare a {@link Signature} with necessary additional information prior to signing.
     *
     * <p>
     * <strong>NOTE:</strong>Since this operation modifies the specified Signature object, it should be called
     * <strong>prior</strong> to marshalling the Signature object.
     * </p>
     *
     * <p>
     * The following Signature values will be added:
     * <ul>
     * <li>signature algorithm URI</li>
     * <li>canonicalization algorithm URI</li>
     * <li>HMAC output length (if applicable and a value is configured)</li>
     * <li>a {@link KeyInfo} element representing the signing credential</li>
     * </ul>
     * </p>
     *
     * <p>
     * Existing (non-null) values of these parameters on the specified signature will <strong>NOT</strong> be
     * overwritten, however.
     * </p>
     *
     * <p>
     * All values are determined by the specified {@link SecurityConfiguration}. If a security configuration is not
     * supplied, the global security configuration ({@link Configuration#getGlobalSecurityConfiguration()}) will be
     * used.
     * </p>
     *
     * <p>
     * The signature algorithm URI and optional HMAC output length are derived from the signing credential.
     * </p>
     *
     * <p>
     * The KeyInfo to be generated is based on the {@link NamedKeyInfoGeneratorManager} defined in the security
     * configuration, and is determined by the type of the signing credential and an optional KeyInfo generator manager
     * name. If the latter is ommited, the default manager ({@link NamedKeyInfoGeneratorManager#getDefaultManager()})
     * of the security configuration's named generator manager will be used.
     * </p>
     *
     * @param signature the Signature to be updated
     * @param signingCredential the credential with which the Signature will be computed
     * @param config the SecurityConfiguration to use (may be null)
     * @param keyInfoGenName the named KeyInfoGeneratorManager configuration to use (may be null)
     * @throws SecurityException thrown if there is an error generating the KeyInfo from the signing credential
     */
    public static void prepareSignatureParams(Signature signature, Credential signingCredential,
                                              SecurityConfiguration config, String keyInfoGenName) throws SecurityException {
        Logger log = getLogger();

        SecurityConfiguration secConfig;
        if (config != null) {
            secConfig = config;
        } else {
            secConfig = GlobalSecurityConfiguration.getGlobalSecurityConfiguration();
        }

        // The algorithm URI is derived from the credential
        String signAlgo = signature.getSignatureAlgorithm();
        if (signAlgo == null) {
            signAlgo = secConfig.getSignatureAlgorithmURI(signingCredential);
            signature.setSignatureAlgorithm(signAlgo);
        }

        // If we're doing HMAC, set the output length
        if (SecurityHelper.isHMAC(signAlgo)) {
            if (signature.getHMACOutputLength() == null) {
                signature.setHMACOutputLength(secConfig.getSignatureHMACOutputLength());
            }
        }

        if (signature.getCanonicalizationAlgorithm() == null) {
            signature.setCanonicalizationAlgorithm(secConfig.getSignatureCanonicalizationAlgorithm());
        }

        if (signature.getKeyInfo() == null) {
            KeyInfoGenerator kiGenerator = getKeyInfoGenerator(signingCredential, secConfig, keyInfoGenName);
            if (kiGenerator != null) {
                try {
                    KeyInfo keyInfo = kiGenerator.generate(signingCredential);
                    signature.setKeyInfo(keyInfo);
                } catch (SecurityException e) {
                    log.error("Error generating KeyInfo from credential", e);
                    throw e;
                }
            } else {
                log.info("No factory for named KeyInfoGenerator {} was found for credential type {}", keyInfoGenName,
                         signingCredential.getCredentialType().getName());
                log.info("No KeyInfo will be generated for Signature");
            }
        }
    }

    /**
     * Build an instance of {@link EncryptionParameters} suitable for passing to an
     * {@link org.opensaml.xml.encryption.Encrypter}.
     *
     * <p>
     * The following parameter values will be added:
     * <ul>
     * <li>the encryption credential (optional)</li>
     * <li>encryption algorithm URI</li>
     * <li>an appropriate {@link KeyInfoGenerator} instance which will be used to generate a {@link KeyInfo} element
     * from the encryption credential</li>
     * </ul>
     * </p>
     *
     * <p>
     * All values are determined by the specified {@link SecurityConfiguration}. If a security configuration is not
     * supplied, the global security configuration ({@link Configuration#getGlobalSecurityConfiguration()}) will be
     * used.
     * </p>
     *
     * <p>
     * The encryption algorithm URI is derived from the optional supplied encryption credential. If omitted, the value
     * of {@link SecurityConfiguration#getAutoGeneratedDataEncryptionKeyAlgorithmURI()} will be used.
     * </p>
     *
     * <p>
     * The KeyInfoGenerator to be used is based on the {@link NamedKeyInfoGeneratorManager} defined in the security
     * configuration, and is determined by the type of the signing credential and an optional KeyInfo generator manager
     * name. If the latter is ommited, the default manager ({@link NamedKeyInfoGeneratorManager#getDefaultManager()})
     * of the security configuration's named generator manager will be used.
     * </p>
     *
     * @param encryptionCredential the credential with which the data will be encrypted (may be null)
     * @param config the SecurityConfiguration to use (may be null)
     * @param keyInfoGenName the named KeyInfoGeneratorManager configuration to use (may be null)
     * @return a new instance of EncryptionParameters
     */
    public static DataEncryptionParameters buildDataEncryptionParams(Credential encryptionCredential,
                                                                 SecurityConfiguration config, String keyInfoGenName) {
        Logger log = getLogger();

        SecurityConfiguration secConfig;
        if (config != null) {
            secConfig = config;
        } else {
            secConfig = GlobalSecurityConfiguration.getGlobalSecurityConfiguration();
        }

        DataEncryptionParameters encParams = new DataEncryptionParameters();
        encParams.setEncryptionCredential(encryptionCredential);

        if (encryptionCredential == null) {
            encParams.setAlgorithm(secConfig.getAutoGeneratedDataEncryptionKeyAlgorithmURI());
        } else {
            encParams.setAlgorithm(secConfig.getDataEncryptionAlgorithmURI(encryptionCredential));

            KeyInfoGenerator kiGenerator = getKeyInfoGenerator(encryptionCredential, secConfig, keyInfoGenName);
            if (kiGenerator != null) {
                encParams.setKeyInfoGenerator(kiGenerator);
            } else {
                log.info("No factory for named KeyInfoGenerator {} was found for credential type{}", keyInfoGenName,
                         encryptionCredential.getCredentialType().getName());
                log.info("No KeyInfo will be generated for EncryptedData");
            }
        }

        return encParams;
    }

    /**
     * Build an instance of {@link KeyEncryptionParameters} suitable for passing to an
     * {@link org.opensaml.xml.encryption.Encrypter}.
     *
     * <p>
     * The following parameter values will be added:
     * <ul>
     * <li>the key encryption credential</li>
     * <li>key transport encryption algorithm URI</li>
     * <li>an appropriate {@link KeyInfoGenerator} instance which will be used to generate a {@link KeyInfo} element
     * from the key encryption credential</li>
     * <li>intended recipient of the resultant encrypted key (optional)</li>
     * </ul>
     * </p>
     *
     * <p>
     * All values are determined by the specified {@link SecurityConfiguration}. If a security configuration is not
     * supplied, the global security configuration ({@link Configuration#getGlobalSecurityConfiguration()}) will be
     * used.
     * </p>
     *
     * <p>
     * The encryption algorithm URI is derived from the optional supplied encryption credential. If omitted, the value
     * of {@link SecurityConfiguration#getAutoGeneratedDataEncryptionKeyAlgorithmURI()} will be used.
     * </p>
     *
     * <p>
     * The KeyInfoGenerator to be used is based on the {@link NamedKeyInfoGeneratorManager} defined in the security
     * configuration, and is determined by the type of the signing credential and an optional KeyInfo generator manager
     * name. If the latter is ommited, the default manager ({@link NamedKeyInfoGeneratorManager#getDefaultManager()})
     * of the security configuration's named generator manager will be used.
     * </p>
     *
     * @param encryptionCredential the credential with which the key will be encrypted
     * @param wrappedKeyAlgorithm the JCA key algorithm name of the key to be encrypted (may be null)
     * @param config the SecurityConfiguration to use (may be null)
     * @param keyInfoGenName the named KeyInfoGeneratorManager configuration to use (may be null)
     * @param recipient the intended recipient of the resultant encrypted key, typically the owner of the key encryption
     *            key (may be null)
     * @return a new instance of KeyEncryptionParameters
     * @throws SecurityException if encryption credential is not supplied
     *
     */
    public static KeyEncryptionParameters buildKeyEncryptionParams(Credential encryptionCredential,
                                                                   String wrappedKeyAlgorithm, SecurityConfiguration config, String keyInfoGenName, String recipient)
        throws SecurityException {
        Logger log = getLogger();

        SecurityConfiguration secConfig;
        if (config != null) {
            secConfig = config;
        } else {
            secConfig = GlobalSecurityConfiguration.getGlobalSecurityConfiguration();
        }

        KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
        kekParams.setEncryptionCredential(encryptionCredential);

        if (encryptionCredential == null) {
            throw new SecurityException("Key encryption credential may not be null");
        }

        kekParams.setAlgorithm(secConfig.getKeyTransportEncryptionAlgorithmURI(encryptionCredential,
                                                                               wrappedKeyAlgorithm));

        KeyInfoGenerator kiGenerator = getKeyInfoGenerator(encryptionCredential, secConfig, keyInfoGenName);
        if (kiGenerator != null) {
            kekParams.setKeyInfoGenerator(kiGenerator);
        } else {
            log.info("No factory for named KeyInfoGenerator {} was found for credential type {}", keyInfoGenName,
                     encryptionCredential.getCredentialType().getName());
            log.info("No KeyInfo will be generated for EncryptedKey");
        }

        kekParams.setRecipient(recipient);

        return kekParams;
    }

    /**
     * Obtains a {@link KeyInfoGenerator} for the specified {@link Credential}.
     *
     * <p>
     * The KeyInfoGenerator returned is based on the {@link NamedKeyInfoGeneratorManager} defined by the specified
     * security configuration via {@link SecurityConfiguration#getKeyInfoGeneratorManager()}, and is determined by the
     * type of the signing credential and an optional KeyInfo generator manager name. If the latter is ommited, the
     * default manager ({@link NamedKeyInfoGeneratorManager#getDefaultManager()}) of the security configuration's
     * named generator manager will be used.
     * </p>
     *
     * <p>
     * The generator is determined by the specified {@link SecurityConfiguration}. If a security configuration is not
     * supplied, the global security configuration ({@link Configuration#getGlobalSecurityConfiguration()}) will be
     * used.
     * </p>
     *
     * @param credential the credential for which a generator is desired
     * @param config the SecurityConfiguration to use (may be null)
     * @param keyInfoGenName the named KeyInfoGeneratorManager configuration to use (may be null)
     * @return a KeyInfoGenerator appropriate for the specified credential
     */
    public static KeyInfoGenerator getKeyInfoGenerator(Credential credential, SecurityConfiguration config,
                                                       String keyInfoGenName) {

        SecurityConfiguration secConfig;
        if (config != null) {
            secConfig = config;
        } else {
            secConfig = GlobalSecurityConfiguration.getGlobalSecurityConfiguration();
        }

        NamedKeyInfoGeneratorManager kiMgr = secConfig.getKeyInfoGeneratorManager();
        if (kiMgr != null) {
            KeyInfoGeneratorFactory kiFactory = null;
            if (DataTypeHelper.isEmpty(keyInfoGenName)) {
                kiFactory = kiMgr.getDefaultManager().getFactory(credential);
            } else {
                kiFactory = kiMgr.getFactory(keyInfoGenName, credential);
            }
            if (kiFactory != null) {
                return kiFactory.newInstance();
            }
        }
        return null;
    }

    /**
     * Get an SLF4J Logger.
     *
     * @return a Logger instance
     */
    private static Logger getLogger() {
        return LoggerFactory.getLogger(SecurityHelper.class);
    }

    static {
        // We use some Apache XML Security utility functions, so need to make sure library
        // is initialized.
        if (!Init.isInitialized()) {
            Init.init();
        }

        // Additional algorithm URI to JCA key algorithm mappings, beyond what is currently
        // supplied in the Apache XML Security mapper config.
        dsaAlgorithmURIs = new LazySet<String>();
        dsaAlgorithmURIs.add(SignatureConstants.ALGO_ID_SIGNATURE_DSA);

        ecdsaAlgorithmURIs = new LazySet<String>();
        ecdsaAlgorithmURIs.add(SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1);
        ecdsaAlgorithmURIs.add(SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA256);
        ecdsaAlgorithmURIs.add(SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA384);
        ecdsaAlgorithmURIs.add(SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA512);

        rsaAlgorithmURIs = new HashSet<String>(10);
        rsaAlgorithmURIs.add(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        rsaAlgorithmURIs.add(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        rsaAlgorithmURIs.add(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA384);
        rsaAlgorithmURIs.add(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512);
        rsaAlgorithmURIs.add(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512);
        rsaAlgorithmURIs.add(SignatureConstants.ALGO_ID_SIGNATURE_RSA_RIPEMD160);
        rsaAlgorithmURIs.add(SignatureConstants.ALGO_ID_SIGNATURE_NOT_RECOMMENDED_RSA_MD5);
    }
}