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

package org.opensaml.compat.security;

import javax.servlet.ServletRequest;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;

/**
 * An adapter that exposes the X.509 certificates contained in the servlet request attribute.
 */
public class ServletRequestX509CredentialAdapter extends BasicX509Credential implements X509Credential {

    /** Servlet request attribute to pull certificate info from. */
    public static final String X509_CERT_REQUEST_ATTRIBUTE = "javax.servlet.request.X509Certificate";

    /**
     * Constructor.
     *
     * @param request the servlet request
     */
    public ServletRequestX509CredentialAdapter(ServletRequest request) {
        super(null);
        X509Certificate[] chain = (X509Certificate[]) request.getAttribute(X509_CERT_REQUEST_ATTRIBUTE);
        if (chain == null || chain.length == 0) {
            throw new IllegalArgumentException("Servlet request does not contain X.509 certificates in attribute "
                    + X509_CERT_REQUEST_ATTRIBUTE);
        }
        setEntityCertificate(chain[0]);
        setEntityCertificateChain(Arrays.asList(chain));
        setUsageType(UsageType.SIGNING);
    }
}