/*
 * Copyright 2011 Vladimir Schaefer
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
package org.springframework.security.saml.trust;

import org.opensaml.xml.security.x509.X509Credential;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Class can be used to initialize new SSL/TLS connections with client/server authentication. Uses a static credential
 * for determining private key and certificate chain.
 */
public class X509KeyManager implements javax.net.ssl.X509KeyManager {

    private static final String ALIAS_NAME = "constantAlias";
    private static final String[] ALIAS = new String[] { ALIAS_NAME };

    private String[] aliases;
    private String alias;
    private PrivateKey privateKey;
    private X509Certificate[] chain;

    /**
     * Credential used for authentication of the server/client.
     *
     * @param credential credential or null for manager returning always empty values
     */
    public X509KeyManager(X509Credential credential) {
        if (credential != null) {
            this.privateKey = credential.getPrivateKey();
            this.chain = credential.getEntityCertificateChain().toArray(new X509Certificate[credential.getEntityCertificateChain().size()]);
            this.alias = ALIAS_NAME;
            this.aliases = ALIAS;
        } else {
            this.privateKey = null;
            this.chain = null;
            this.alias = null;
            this.aliases = null;
        }
    }

    public String[] getClientAliases(String s, Principal[] principals) {
        return aliases;
    }

    public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {
        return alias;
    }

    public String[] getServerAliases(String s, Principal[] principals) {
        return aliases;
    }

    public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
        return alias;
    }

    public X509Certificate[] getCertificateChain(String s) {
        return chain;
    }

    public PrivateKey getPrivateKey(String s) {
        return privateKey;
    }

}