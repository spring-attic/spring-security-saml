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

import java.util.ArrayList;

import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.impl.BasicKeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.impl.KeyInfoProvider;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.impl.provider.DSAKeyValueProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.InlineX509DataProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.RSAKeyValueProvider;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

/**
 * A utility class which programatically builds an instance of {@link BasicSecurityConfiguration}
 * which has reasonable default values for the various configuration parameters.
 */
public class DefaultSecurityConfigurationBootstrap {

    /** Constructor. */
    protected DefaultSecurityConfigurationBootstrap() {}

    /**
     * Build and return a default configuration.
     *
     * @return a new basic security configuration with reasonable default values
     */
    public static BasicSecurityConfiguration buildDefaultConfig() {
        BasicSecurityConfiguration config = new BasicSecurityConfiguration();

        populateSignatureParams(config);
        populateEncryptionParams(config);
        populateKeyInfoCredentialResolverParams(config);
        populateKeyInfoGeneratorManager(config);
        populateKeyParams(config);

        return config;
    }

    /**
     * Populate signature-related parameters.
     *
     * @param config the security configuration to populate
     */
    protected static void populateSignatureParams(BasicSecurityConfiguration config) {
        // Asymmetric key algorithms
        config.registerSignatureAlgorithmURI("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        config.registerSignatureAlgorithmURI("DSA", SignatureConstants.ALGO_ID_SIGNATURE_DSA);
        config.registerSignatureAlgorithmURI("EC", SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1);

        // HMAC algorithms
        config.registerSignatureAlgorithmURI("AES", SignatureConstants.ALGO_ID_MAC_HMAC_SHA1);
        config.registerSignatureAlgorithmURI("DESede", SignatureConstants.ALGO_ID_MAC_HMAC_SHA1);

        // Other signature-related params
        config.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        config.setSignatureHMACOutputLength(null);
        config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA1);
    }

    /**
     * Populate encryption-related parameters.
     *
     * @param config the security configuration to populate
     */
    protected static void populateEncryptionParams(BasicSecurityConfiguration config) {
        // Data encryption URI's
        config.registerDataEncryptionAlgorithmURI("AES", 128, EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
        config.registerDataEncryptionAlgorithmURI("AES", 192, EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192);
        config.registerDataEncryptionAlgorithmURI("AES", 256, EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);
        config.registerDataEncryptionAlgorithmURI("DESede", 168, EncryptionConstants.ALGO_ID_BLOCKCIPHER_TRIPLEDES);
        config.registerDataEncryptionAlgorithmURI("DESede", 192, EncryptionConstants.ALGO_ID_BLOCKCIPHER_TRIPLEDES);

        // Key encryption URI's

        // Asymmetric key transport algorithms
        config.registerKeyTransportEncryptionAlgorithmURI("RSA", null, "AES", EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        config.registerKeyTransportEncryptionAlgorithmURI("RSA", null, "DESede", EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

        // Symmetric key wrap algorithms
        config.registerKeyTransportEncryptionAlgorithmURI("AES", 128, null, EncryptionConstants.ALGO_ID_KEYWRAP_AES128);
        config.registerKeyTransportEncryptionAlgorithmURI("AES", 192, null, EncryptionConstants.ALGO_ID_KEYWRAP_AES192);
        config.registerKeyTransportEncryptionAlgorithmURI("AES", 256, null, EncryptionConstants.ALGO_ID_KEYWRAP_AES256);
        config.registerKeyTransportEncryptionAlgorithmURI("DESede", 168, null, EncryptionConstants.ALGO_ID_KEYWRAP_TRIPLEDES);
        config.registerKeyTransportEncryptionAlgorithmURI("DESede", 192, null, EncryptionConstants.ALGO_ID_KEYWRAP_TRIPLEDES);

        // Other encryption-related params
        config.setAutoGeneratedDataEncryptionKeyAlgorithmURI(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
    }

    /**
     * Populate KeyInfoCredentialResolver-related parameters.
     *
     * @param config the security configuration to populate
     */
    protected static void populateKeyInfoCredentialResolverParams(BasicSecurityConfiguration config) {
        // Basic resolver for inline info
        ArrayList<KeyInfoProvider> providers = new ArrayList<KeyInfoProvider>();
        providers.add( new RSAKeyValueProvider() );
        providers.add( new DSAKeyValueProvider() );
        providers.add( new InlineX509DataProvider() );

        KeyInfoCredentialResolver resolver = new BasicProviderKeyInfoCredentialResolver(providers);
        config.setDefaultKeyInfoCredentialResolver(resolver);
    }

    /**
     * Populate KeyInfoGeneratorManager-related parameters.
     *
     * @param config the security configuration to populate
     */
    protected static void populateKeyInfoGeneratorManager(BasicSecurityConfiguration config) {
        NamedKeyInfoGeneratorManager namedManager = new NamedKeyInfoGeneratorManager();
        config.setKeyInfoGeneratorManager(namedManager);

        namedManager.setUseDefaultManager(true);
        KeyInfoGeneratorManager defaultManager = namedManager.getDefaultManager();

        // Generator for basic Credentials
        BasicKeyInfoGeneratorFactory basicFactory = new BasicKeyInfoGeneratorFactory();
        basicFactory.setEmitPublicKeyValue(true);

        // Generator for X509Credentials
        X509KeyInfoGeneratorFactory x509Factory = new X509KeyInfoGeneratorFactory();
        x509Factory.setEmitEntityCertificate(true);
        x509Factory.setEmitEntityCertificateChain(true);

        defaultManager.registerFactory(basicFactory);
        defaultManager.registerFactory(x509Factory);
    }

    /**
     * Populate misc key-related parameters.
     *
     * @param config the security configuration to populate
     */
    protected static void populateKeyParams(BasicSecurityConfiguration config) {
        // Maybe populate some DSA parameters here, if there are commonly accepcted default values
    }

}
