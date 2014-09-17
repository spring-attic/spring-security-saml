package org.springframework.security.saml.trust.httpclient;

import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.httpclient.protocol.SecureProtocolSocketFactory;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.trust.TrustEngine;
import org.opensaml.xml.security.x509.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.trust.CertPathPKIXTrustEvaluator;
import org.springframework.security.saml.trust.X509KeyManager;
import org.springframework.security.saml.trust.X509TrustManager;
import org.springframework.security.saml.util.SAMLUtil;

import javax.annotation.PostConstruct;
import javax.net.ssl.HostnameVerifier;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Socket factory can be used with HTTP Client for creation of SSL/TLS sockets. Implementation uses internal KeyManager
 * for loading of all public keys. Trust is verified using PKIX algorithm based on trust anchors defined as trusted
 * with property trustedKeys (all all keys on KeyManager when trustKeys are null). Implementation uses hostname verification
 * algorithm.
 */
public class TLSProtocolSocketFactory implements SecureProtocolSocketFactory {

    private static final Logger log = LoggerFactory.getLogger(TLSProtocolSocketFactory.class);

    /**
     * Storage for all available keys.
     */
    private KeyManager keyManager;

    /**
     * Hostname verifier to use for verification of SSL connections, e.g. for ArtifactResolution.
     */
    private String sslHostnameVerification = "default";

    /**
     * Keys used as anchors for trust verification when PKIX mode is enabled for the local entity. In case value is null
     * all keys in the keyStore will be treated as trusted.
     */
    private Set<String> trustedKeys;

    /**
     * Internally used socket factory where createSocket methods are delegated to.
     */
    private SecureProtocolSocketFactory socketFactory;

    /**
     * Default constructor, which initializes socket factory to trust all keys with alias from the trusted
     * keys as found in the keyManager.
     *
     * @param keyManager key manager includes all cryptography material for the SAML instance
     * @param trustedKeys when not set all certificates included in the keystore will be used as trusted certificate authorities. When specified, only keys with the defined aliases will be used for trust evaluation.
     * @param sslHostnameVerification type of hostname verification
     */
    public TLSProtocolSocketFactory(KeyManager keyManager, Set<String> trustedKeys, String sslHostnameVerification) {
        this.keyManager = keyManager;
        this.sslHostnameVerification = sslHostnameVerification;
        this.trustedKeys = trustedKeys;
        this.socketFactory = initializeDelegate();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return socketFactory.createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int clientPort) throws IOException {
        return socketFactory.createSocket(host, port, localHost, clientPort);
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        return socketFactory.createSocket(socket, host, port, autoClose);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort, HttpConnectionParams connParams) throws IOException {
        return socketFactory.createSocket(host, port, localHost, localPort, connParams);
    }

    /**
     * Initializes internal SocketFactory used to create all sockets. By default uses PKIX algorithm with
     * configured trusted keys as trust anchors.
     *
     * @return socket factory
     */
    protected SecureProtocolSocketFactory initializeDelegate() {

        CertPathPKIXValidationOptions pkixOptions = new CertPathPKIXValidationOptions();
        PKIXValidationInformationResolver pkixResolver = getPKIXResolver();
        CertPathPKIXTrustEvaluator pkixTrustEvaluator = new CertPathPKIXTrustEvaluator(pkixOptions);
        TrustEngine<X509Credential> trustEngine = new PKIXX509CredentialTrustEngine(pkixResolver, pkixTrustEvaluator, new BasicX509CredentialNameEvaluator());

        X509KeyManager keyManager = new X509KeyManager((X509Credential) this.keyManager.getDefaultCredential());
        X509TrustManager trustManager = new X509TrustManager(new CriteriaSet(), trustEngine);
        HostnameVerifier hostnameVerifier = SAMLUtil.getHostnameVerifier(sslHostnameVerification);

        if (isHostnameVerificationSupported()) {
            return new org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory(keyManager, trustManager, hostnameVerifier);
        } else {
            return new org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory(keyManager, trustManager);
        }

    }

    /**
     * Method is expected to construct information resolver with all trusted data available for the given provider.
     *
     * @return information resolver
     */
    protected PKIXValidationInformationResolver getPKIXResolver() {

        // Use all available keys
        if (trustedKeys == null) {
            trustedKeys = keyManager.getAvailableCredentials();
        }

        // Resolve allowed certificates to build the anchors
        List<X509Certificate> certificates = new ArrayList<X509Certificate>(trustedKeys.size());
        for (String key : trustedKeys) {
            log.debug("Adding PKIX trust anchor {} for SSL/TLS verification {}", key);
            certificates.add(keyManager.getCertificate(key));
        }

        List<PKIXValidationInformation> info = new LinkedList<PKIXValidationInformation>();
        info.add(new BasicPKIXValidationInformation(certificates, null, 4));
        return new StaticPKIXValidationInformationResolver(info, null);

    }

    /**
     * Check for the latest OpenSAML library. Support for HostnameVerification was added in openws-1.5.1 and
     * customers might use previous versions of OpenSAML.
     *
     * @return true when OpenSAML library support hostname verification
     */
    protected boolean isHostnameVerificationSupported() {
        try {
            org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory.class.getConstructor(javax.net.ssl.X509KeyManager.class, javax.net.ssl.X509TrustManager.class, javax.net.ssl.HostnameVerifier.class);
            return true;
        } catch (NoSuchMethodException e) {
            log.warn("HostnameVerification is not supported, update your OpenSAML libraries");
            return false;
        }
    }

}
