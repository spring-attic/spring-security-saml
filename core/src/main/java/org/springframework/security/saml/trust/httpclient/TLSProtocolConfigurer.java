package org.springframework.security.saml.trust.httpclient;

import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.key.KeyManager;

import java.util.Set;

/**
 * Class initializes instance of TLSProtocolSocketFactory and registers is at one of the protocol
 * inside HTTP Client. It also automatically makes the MetadataManager dependant on this bean.
 */
public class TLSProtocolConfigurer implements InitializingBean {

    /**
     * Name of protocol to register.
     */
    private String protocolName = "https";

    /*
     * Default port of protocol.
     */
    private int protocolPort = 443;

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
     * Initializes the socket factory and registers it to the HTTP Client's protocol registry.
     *
     * @throws Exception error
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        ProtocolSocketFactory socketFactory = new TLSProtocolSocketFactory(keyManager, trustedKeys, sslHostnameVerification);
        Protocol p = new Protocol(protocolName, socketFactory, protocolPort);
        Protocol.registerProtocol(protocolName, p);
    }

    /**
     * Key manager includes all cryptography material for the SAML instance.
     *
     * @param keyManager key manager
     */
    @Autowired
    public void setKeyManager(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    /**
     * Hostname verifier to use for verification of SSL connections. Default value is "default", other supported options
     * are "defaultAndLocalhost", "strict" and "allowAll".
     *
     * @param sslHostnameVerification hostname verification type flag
     */
    public void setSslHostnameVerification(String sslHostnameVerification) {
        this.sslHostnameVerification = sslHostnameVerification;
    }

    /**
     * When not set all certificates included in the keystore will be used as trusted certificate authorities. When specified,
     * only keys with the defined aliases will be used for trust evaluation.
     *
     * @param trustedKeys trusted keys
     */
    public void setTrustedKeys(Set<String> trustedKeys) {
        this.trustedKeys = trustedKeys;
    }

    /**
     * Name of protocol (ID) to register to HTTP Client, https by default.
     *
     * @param protocolName protocol
     */
    public void setProtocolName(String protocolName) {
        this.protocolName = protocolName;
    }

    /**
     * Default port for protocol, 443 by default.
     *
     * @param protocolPort port
     */
    public void setProtocolPort(int protocolPort) {
        this.protocolPort = protocolPort;
    }

}
