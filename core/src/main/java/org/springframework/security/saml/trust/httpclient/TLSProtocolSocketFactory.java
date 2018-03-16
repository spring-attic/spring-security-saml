package org.springframework.security.saml.trust.httpclient;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import net.shibboleth.utilities.java.support.httpclient.TLSSocketFactory;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.apache.http.HttpHost;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.protocol.HttpContext;
import org.opensaml.security.trust.TrustEngine;
import org.opensaml.security.x509.PKIXValidationInformation;
import org.opensaml.security.x509.PKIXValidationInformationResolver;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.security.x509.impl.BasicPKIXValidationInformation;
import org.opensaml.security.x509.impl.BasicX509CredentialNameEvaluator;
import org.opensaml.security.x509.impl.CertPathPKIXValidationOptions;
import org.opensaml.security.x509.impl.PKIXX509CredentialTrustEngine;
import org.opensaml.security.x509.impl.StaticPKIXValidationInformationResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.trust.CertPathPKIXTrustEvaluator;
import org.springframework.security.saml.trust.X509KeyManager;
import org.springframework.security.saml.trust.X509TrustManager;
import org.springframework.security.saml.util.SAMLUtil;

/**
 * Socket factory can be used with HTTP Client for creation of SSL/TLS sockets. Implementation uses internal KeyManager
 * for loading of all public keys. Trust is verified using PKIX algorithm based on trust anchors defined as trusted
 * with property trustedKeys (all all keys on KeyManager when trustKeys are null). Implementation uses hostname verification
 * algorithm.
 */
public class TLSProtocolSocketFactory implements ConnectionSocketFactory {

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
    private LayeredConnectionSocketFactory socketFactory;

    /**
     * Default constructor, which initializes socket factory to trust all keys with alias from the trusted
     * keys as found in the keyManager.
     *
     * @param keyManager key manager includes all cryptography material for the SAML instance
     * @param trustedKeys when not set all certificates included in the keystore will be used as trusted certificate authorities. When specified, only keys with the defined aliases will be used for trust evaluation.
     * @param sslHostnameVerification type of hostname verification
     */
    public TLSProtocolSocketFactory(KeyManager keyManager, Set<String> trustedKeys, String sslHostnameVerification)
        throws KeyManagementException, NoSuchAlgorithmException {
        this.keyManager = keyManager;
        this.sslHostnameVerification = sslHostnameVerification;
        this.trustedKeys = trustedKeys;
        this.socketFactory = initializeDelegate();
    }


    /**
     * Initializes internal SocketFactory used to create all sockets. By default uses PKIX algorithm with
     * configured trusted keys as trust anchors.
     *
     * @return socket factory
     */
    protected LayeredConnectionSocketFactory initializeDelegate()
        throws KeyManagementException, NoSuchAlgorithmException {

        CertPathPKIXValidationOptions pkixOptions = new CertPathPKIXValidationOptions();
        PKIXValidationInformationResolver pkixResolver = getPKIXResolver();
        CertPathPKIXTrustEvaluator pkixTrustEvaluator = new CertPathPKIXTrustEvaluator(pkixOptions);
        TrustEngine<X509Credential> trustEngine = new PKIXX509CredentialTrustEngine(pkixResolver, pkixTrustEvaluator, new BasicX509CredentialNameEvaluator());

        X509KeyManager keyManager = new X509KeyManager((X509Credential) this.keyManager.getDefaultCredential());
        X509TrustManager trustManager = new X509TrustManager(new CriteriaSet(), trustEngine);
        X509HostnameVerifier hostnameVerifier = SAMLUtil.getHostnameVerifier(sslHostnameVerification);

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(new javax.net.ssl.KeyManager[] {keyManager},
                new TrustManager[] {trustManager},
                new SecureRandom()
        );
        if (isHostnameVerificationSupported()) {
            return new TLSSocketFactory(sc, hostnameVerifier);
        } else {
            return new TLSSocketFactory(sc);
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
            TLSSocketFactory.class.getConstructor(SSLContext.class, X509HostnameVerifier.class);
            return true;
        } catch (NoSuchMethodException e) {
            log.warn("HostnameVerification is not supported, update your OpenSAML libraries");
            return false;
        }
    }

    @Override
    public Socket createSocket(HttpContext context) throws IOException {
        return socketFactory.createSocket(context);
    }

    @Override
    public Socket connectSocket(int connectTimeout, Socket sock, HttpHost host, InetSocketAddress remoteAddress, InetSocketAddress localAddress, HttpContext context)
        throws IOException {
        return socketFactory.connectSocket(connectTimeout, sock, host, remoteAddress, localAddress, context);
    }
}
