/* Copyright 2009 Vladimir Schäfer
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
package org.springframework.security.saml.websso;

import org.opensaml.common.SAMLException;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.util.Base64;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.util.Assert;

import java.security.cert.CertificateEncodingException;
import java.util.List;

/**
 * Class implements processing of the SAML Holder-of-Key Browser SSO profile as per
 * http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-holder-of-key-browser-sso-cs-02.pdf.
 *
 * @author Vladimir Schäfer
 */
public class WebSSOProfileConsumerHoKImpl extends WebSSOProfileConsumerImpl implements WebSSOProfileConsumer {

    @Override
    public String getProfileIdentifier() {
        return SAMLConstants.SAML2_HOK_WEBSSO_PROFILE_URI;
    }

    /**
     * Verifies validity of Subject element as per http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml2-holder-of-key-cs-02.pdf  and
     * http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-holder-of-key-browser-sso-cs-02.pdf.
     * <p>
     * Only verification based on X509Certificate content of the X509Data in KeyInfo is supported. Subject is deemed as
     * confirmed when at least one of the certificates present in the SubjectConfirmation matches the one used in TLS/SSL
     * client authentication. No verification on trust or validity of the certificate itself is performed.
     *
     * @param subject subject to validate
     * @param request request
     * @param context context
     * @throws org.opensaml.common.SAMLException
     *          error validating the object
     * @throws org.opensaml.xml.encryption.DecryptionException
     *          in case the NameID can't be decrypted
     */
    protected void verifySubject(Subject subject, AuthnRequest request, SAMLMessageContext context) throws SAMLException, DecryptionException {

        String userAgentCertificate = getUserAgentBase64Certificate(context);

        for (SubjectConfirmation confirmation : subject.getSubjectConfirmations()) {

            if (SubjectConfirmation.METHOD_HOLDER_OF_KEY.equals(confirmation.getMethod())) {

                log.debug("Processing Holder-of-Key subject confirmation");
                SubjectConfirmationData data = confirmation.getSubjectConfirmationData();

                // HoK must have confirmation 554
                if (data == null) {
                    log.debug("HoK SubjectConfirmation invalidated by missing confirmation data");
                    continue;
                }

                if (!(data instanceof KeyInfoConfirmationDataType)) {
                    log.debug("HoK SubjectConfirmation invalidated by confirmation data not being of KeyInformationDataType type");
                    continue;
                }

                // Verify found certificate corresponds to peer certificate from SSL/TLS
                KeyInfoConfirmationDataType keyInfoConfirmation = (KeyInfoConfirmationDataType) data;
                boolean foundUserAgent = false;
                info:
                for (XMLObject xmlInfo : keyInfoConfirmation.getKeyInfos()) {
                    KeyInfo keyInfo = (KeyInfo) xmlInfo;
                    List<String> certificates = SAMLUtil.getBase64EncodeCertificates(keyInfo);
                    for (String confirmationCert : certificates) {
                        log.debug("Comparing user agent certificate {} with certificate in HoK key info {}", userAgentCertificate, confirmationCert);
                        if (userAgentCertificate.equals(confirmationCert)) {
                            log.debug("User agent certificate confirmed");
                            foundUserAgent = true;
                            break info;
                        }
                    }
                }
                if (!foundUserAgent) {
                    log.debug("HoK SubjectConfirmation invalidated by confirmation keyInfo not corresponding to certificate supplied by user agent");
                    continue;
                }

                // Validate not before
                if (data.getNotBefore() != null && data.getNotBefore().isAfterNow()) {
                    log.debug("HoK SubjectConfirmation invalidated by notBefore field");
                    continue;
                }

                // Validate not on or after
                if (data.getNotBefore() != null && data.getNotOnOrAfter().isBeforeNow()) {
                    log.debug("HoK SubjectConfirmation invalidated by expired notOnOrAfter");
                    continue;
                }

                // Validate in response to if present
                if (request != null) {
                    if (data.getInResponseTo() != null) {
                        if (!data.getInResponseTo().equals(request.getID())) {
                            log.debug("HoK SubjectConfirmation invalidated by invalid in response to field");
                            continue;
                        }
                    }
                }

                // Validate recipient if present
                if (data.getRecipient() != null) {
                    try {
                        verifyEndpoint(context.getLocalEntityEndpoint(), data.getRecipient());
                    } catch (SAMLException e) {
                        log.debug("HoK SubjectConfirmation invalidated by recipient assertion consumer URL, found {}", data.getRecipient());
                        continue;
                    }
                }

                // Was the subject confirmed by this confirmation data? If so let's store the subject in context.
                NameID nameID;
                if (subject.getEncryptedID() != null) {
                    Assert.notNull(context.getLocalDecrypter(), "Can't decrypt NameID, no decrypter is set in the context");
                    nameID = (NameID) context.getLocalDecrypter().decrypt(subject.getEncryptedID());
                } else {
                    nameID = subject.getNameID();
                }
                context.setSubjectNameIdentifier(nameID);
                return;

            }

        }

        throw new SAMLException("Assertion invalidated by subject confirmation - can't be confirmed by holder-of-key method");

    }

    /**
     * Method locates user agent certificate used in SSL/TLS and encodes it using base64 for comparison in HoK
     * subject confirmation. Method fails when certificate can't be obtained or encoded.
     *
     * @param context context expected to contain certificate in peerSSLCredential field
     * @return base64 encoded peer certificate
     * @throws SAMLException in case certificate is missing or can't be encoded
     */
    protected String getUserAgentBase64Certificate(SAMLMessageContext context) throws SAMLException {

        if (context.getPeerSSLCredential() == null) {
            throw new SAMLException("Cannot verify Holder-of-Key Assertion, peer SSL/TLS credential is not set in the context");
        }

        try {
            return Base64.encodeBytes(context.getPeerSSLCredential().getEntityCertificate().getEncoded());
        } catch (CertificateEncodingException e) {
            throw new SAMLException("Error base64 encoding peer certificate");
        }

    }

}
