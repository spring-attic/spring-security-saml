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

package org.springframework.security.saml2.util;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

import org.springframework.security.saml2.xml.SimpleKey;

import static org.springframework.util.StringUtils.hasText;

public class InMemoryKeyStore {

    private static final char[] KS_PASSWD = UUID.randomUUID().toString().toCharArray();

    public static InMemoryKeyStore fromKey(SimpleKey key) {
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null, KS_PASSWD);

            byte[] certbytes = X509Utilities.getDER(key.getCertificate());
            Certificate certificate = X509Utilities.getCertificate(certbytes);
            ks.setCertificateEntry(key.getAlias(), certificate);

            if (hasText(key.getPrivateKey())) {
                byte[] keybytes = X509Utilities.getDER(key.getPrivateKey());
                RSAPrivateKey privateKey = X509Utilities.getPrivateKey(keybytes, "RSA");
                ks.setKeyEntry(key.getAlias(), privateKey, key.getPassphrase().toCharArray(), new Certificate[]{certificate});
            }

            return new InMemoryKeyStore(ks);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private KeyStore ks;

    public InMemoryKeyStore(KeyStore ks) {
        this.ks = ks;
    }

    public KeyStore getKeyStore() {
        return ks;
    }


}
