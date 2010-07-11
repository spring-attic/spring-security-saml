/* Copyright 2009 Vladimir Sch�fer
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
package org.springframework.security.saml.key;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Serves as a wrapper for java security KeyStore of JKS type which can be conveniently initialized as a Spring bean.
 * <p>
 * The instance can be inserted into springConfiguration in a following manner:
 * <pre>
 *   <bean id="keyStore" class="org.springframework.security.saml.key.JKSKeyManager">
 *       <constructor-arg index="0" value="d:/keystore.jks" />
 *       <constructor-arg index="1" value="nalle123" />
 *   </bean>
 * </pre>
 * Instances of java.security.KeyStore can then be obtained by calls to the getKeyStore method:
 * <pre>
 *    <constructor-arg index="0">
 *          <bean factory-bean="keyStore" factory-method="getKeyStore" />
 *    </constructor-arg>
 * </pre>
 * </p>
 * <p/>
 * Class also provides convenience methods for loading of certificates and public keys.
 *
 * @author Vladimir Schafer
 */
public class JKSKeyManager {

    private final Logger log = LoggerFactory.getLogger(JKSKeyManager.class);

    /**
     * Keystore to retrieve keys from
     */
    private KeyStore ks;

    /**
     * Default constructor.
     *
     * @param storeFile file pointing to the JKS keystore
     * @param storePass password to access the keystore
     */
    public JKSKeyManager(File storeFile, String storePass) {
        initialize(storeFile, storePass, "JKS");
    }

    /**
     * Initializes the keystore using given properties.
     *
     * @param storeFile file pointing to the JKS keystore
     * @param storePass password to open the keystore
     * @param storeType type of keystore
     */
    private void initialize(File storeFile, String storePass, String storeType) {
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream(storeFile);
            ks = KeyStore.getInstance(storeType);
            ks.load(inputStream, storePass.toCharArray());
        } catch (Exception e) {
            log.error("Error initializing key store", e);
            throw new RuntimeException("Error initializing keystore", e);
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    log.debug("Error closing input stream for keystore.", e);
                }
            }
        }
    }

    /**
     * Returns certificate with the given alias from the keystore.
     *
     * @param alias alias of certificate to find
     *
     * @return certificate with the given alias or null if not found
     */
    public X509Certificate getCertificate(String alias) {
        if (alias == null || alias.length() == 0) {
            return null;
        }
        try {
            return (X509Certificate) ks.getCertificate(alias);
        } catch (Exception e) {
            log.error("Error loading certificate", e);
        }
        return null;
    }

    /**
     * Returns public key with the given alias
     *
     * @param alias alias of the key to find
     *
     * @return public key of the alias or null if not found
     */
    public PublicKey getPublicKey(String alias) {
        X509Certificate x509Certificate = getCertificate(alias);
        if (x509Certificate != null) {
            return x509Certificate.getPublicKey();
        } else {
            return null;
        }
    }

    /**
     * @return returns the initialized key store
     */
    public KeyStore getKeyStore() {
        return ks;
    }
}
