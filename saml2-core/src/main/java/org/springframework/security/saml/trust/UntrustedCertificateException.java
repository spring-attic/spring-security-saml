/*
 * Copyright 2012 Vladimir Schaefer
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

import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.codec.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Exception indicates that verification failed due to the provided chain not being trusted.
 */
public class UntrustedCertificateException extends CertificateException {

    /**
     * Untrusted chain.
     */
    private X509Certificate[] x509Certificates;

    public UntrustedCertificateException(String msg, X509Certificate[] x509Certificates) {
        super(msg);
        this.x509Certificates = x509Certificates;
    }

    /**
     * @return certificates which could not be verified as trusted
     */
    public X509Certificate[] getX509Certificates() {
        return x509Certificates;
    }

    @Override
    public String getMessage() {
        StringBuilder sb = new StringBuilder(150);
        sb.append(super.getMessage());
        if (x509Certificates != null && x509Certificates.length > 0) {
            sb.append("\n\nFollow certificates (in PEM format) presented by the peer. Content between being/end certificate (including) can be stored in a file and imported using keytool, e.g. 'keytool -importcert -file cert.cer -alias certAlias -keystore keystore.jks'). Make sure the presented certificates are issued by your trusted CA before adding them to the keystore.\n\n");
            for (X509Certificate cert : x509Certificates) {
                sb.append("Subject: ").append(cert.getSubjectDN()).append("\n");
                sb.append("Serial number: ").append(cert.getSerialNumber()).append("\n");
                appendThumbPrint(cert, sb);
                sb.append("\n");
                appendCertificate(cert, sb);
                sb.append("\n");
            }
        }
        return sb.toString();
    }

    private static void appendThumbPrint(X509Certificate x509Certificate, StringBuilder sb) {
        sb.append("Thumbprint SHA-1: ");
        appendThumbPrint(x509Certificate, "SHA-1", sb);
        sb.append("\n");
        sb.append("Thumbprint MD5: ");
        appendThumbPrint(x509Certificate, "MD5", sb);
        sb.append("\n");
    }

    private static void appendThumbPrint(X509Certificate cert, String hash, StringBuilder sb) {
        try {
            MessageDigest md = MessageDigest.getInstance(hash);
            byte[] der = cert.getEncoded();
            md.update(der);
            byte[] digest = md.digest();
            char[] encode = Hex.encode(digest);
            appendHexSpace(encode, sb);
        } catch (NoSuchAlgorithmException e) {
            sb.append ("Error calculating thumbprint: " + e.getMessage());
        } catch (CertificateEncodingException e) {
            sb.append("Error calculating thumbprint: " + e.getMessage());
        }
    }

    private static void appendHexSpace(char[] data, StringBuilder sb) {
        for (int i = 1; i <= data.length; i++) {
            sb.append(data[i-1]);
            if ((i%2==0) && (i!=data.length)) {
                sb.append(":");
            }
        }
    }

    private static void appendCertificate(X509Certificate x509Certificate, StringBuilder sb) {
        sb.append("-----BEGIN CERTIFICATE-----\n");
        try {
            String certificate = new String(Base64.encode(x509Certificate.getEncoded()));
            int i = 0;
            while (true) {
                int j = i + 76;
                if (j < certificate.length()) {
                    sb.append(certificate.substring(i, j)).append("\n");
                    i = j;
                } else {
                    sb.append(certificate.substring(i)).append("\n");
                    break;
                }
            }
        } catch (CertificateEncodingException e) {
            sb.append("Cannot encode: ").append(e.getMessage());
        }
        sb.append("-----END CERTIFICATE-----\n");
    }

}
