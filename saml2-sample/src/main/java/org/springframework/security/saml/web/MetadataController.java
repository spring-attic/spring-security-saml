/* Copyright 2011 Vladimir Schafer
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
package org.springframework.security.saml.web;

import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.metadata.*;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.InternalResourceView;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletRequest;
import java.security.KeyStoreException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Class allows manipulation of metadata from web UI.
 */
@Controller
@RequestMapping("/metadata")
public class MetadataController {

    private final Logger log = LoggerFactory.getLogger(MetadataController.class);

    @Autowired
    MetadataGenerator generator;

    @Autowired
    MetadataManager metadataManager;

    @Autowired
    JKSKeyManager keyManager;

    @RequestMapping
    public ModelAndView metadataList() throws MetadataProviderException {

        ModelAndView model = new ModelAndView(new InternalResourceView("/WEB-INF/security/metadataList.jsp", true));

        model.addObject("hostedSP", metadataManager.getHostedSPName());
        model.addObject("spList", metadataManager.getSPEntityNames());
        model.addObject("idpList", metadataManager.getIDPEntityNames());

        return model;

    }

    @RequestMapping(value = "/generate")
    public ModelAndView generateMetadata(HttpServletRequest request) throws KeyStoreException {

        ModelAndView model = new ModelAndView(new InternalResourceView("/WEB-INF/security/metadataGenerator.jsp", true));
        MetadataForm defaultForm = new MetadataForm();

        model.addObject("availableKeys", getAvailablePrivateKeys());
        defaultForm.setBaseURL(getBaseURL(request));
        defaultForm.setEntityId(getEntityId(request));
        defaultForm.setAlias(getEntityId(request));

        model.addObject("metadata", defaultForm);
        return model;

    }

    @RequestMapping(value = "/create")
    public ModelAndView createMetadata(@ModelAttribute("metadata") MetadataForm metadata, BindingResult bindingResult) throws MetadataProviderException, MarshallingException, KeyStoreException {

        new MetadataValidator(metadataManager).validate(metadata, bindingResult);

        if (bindingResult.hasErrors()) {
            ModelAndView modelAndView = new ModelAndView(new InternalResourceView("/WEB-INF/security/metadataGenerator.jsp", true));
            modelAndView.addObject("availableKeys", getAvailablePrivateKeys());
            return modelAndView;
        }

        generator.setEntityId(metadata.getEntityId());
        generator.setEntityAlias(metadata.getAlias());
        generator.setEntityBaseURL(metadata.getBaseURL());
        generator.setSignMetadata(metadata.isSignMetadata());
        generator.setRequestSigned(metadata.isRequestSigned());
        generator.setWantAssertionSigned(metadata.isWantAssertionSigned());
        generator.setSigningKey(metadata.getSigningKey());
        generator.setEncryptionKey(metadata.getEncryptionKey());
        generator.setTlsKey(metadata.getTlsKey());

        // TODO other

        //generator.setBindings();
        //generator.setNameID();

        EntityDescriptor descriptor = generator.generateMetadata();
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        generator.generateExtendedMetadata(extendedMetadata);
        extendedMetadata.setSecurityProfile(metadata.getSecurityProfile());
        extendedMetadata.setRequireLogoutRequestSigned(metadata.isRequireLogoutRequestSigned());
        extendedMetadata.setRequireLogoutResponseSigned(metadata.isRequireLogoutResponseSigned());
        extendedMetadata.setRequireArtifactResolveSigned(metadata.isRequireArtifactResolveSigned());

        if (metadata.isStore()) {

            MetadataMemoryProvider memoryProvider = new MetadataMemoryProvider(descriptor);
            memoryProvider.initialize();
            MetadataProvider metadataProvider = new ExtendedMetadataDelegate(memoryProvider, extendedMetadata);
            metadataManager.addMetadataProvider(metadataProvider);
            metadataManager.setHostedSPName(descriptor.getEntityID());
            metadataManager.setRefreshRequired(true);
            metadataManager.refreshMetadata();

        }

        return displayMetadata(descriptor, extendedMetadata);

    }

    /**
     * Displays stored metadata.
     *
     * @param entityId entity ID of metadata to display
     * @return model and view
     * @throws MetadataProviderException in case metadata can't be located
     * @throws MarshallingException      in case de-serialization into string fails
     */
    @RequestMapping(value = "/display")
    public ModelAndView displayMetadata(@RequestParam("entityId") String entityId) throws MetadataProviderException, MarshallingException {

        EntityDescriptor entityDescriptor = metadataManager.getEntityDescriptor(entityId);
        ExtendedMetadata extendedMetadata = metadataManager.getExtendedMetadata(entityId);

        if (entityDescriptor == null) {
            throw new MetadataProviderException("Metadata with ID " + entityId + " not found");
        }

        return displayMetadata(entityDescriptor, extendedMetadata);

    }

    protected ModelAndView displayMetadata(EntityDescriptor entityDescriptor, ExtendedMetadata extendedMetadata) throws MarshallingException {

        MetadataForm metadata = new MetadataForm();
        String fileName = getFileName(entityDescriptor);

        metadata.setLocal(extendedMetadata.isLocal());
        metadata.setSecurityProfile(extendedMetadata.getSecurityProfile());
        metadata.setSerializedMetadata(getMetadataAsString(entityDescriptor));
        metadata.setConfiguration(getConfiguration(fileName, extendedMetadata));
        metadata.setEntityId(entityDescriptor.getEntityID());
        metadata.setAlias(extendedMetadata.getAlias());
        metadata.setRequireArtifactResolveSigned(extendedMetadata.isRequireArtifactResolveSigned());
        metadata.setRequireLogoutRequestSigned(extendedMetadata.isRequireLogoutRequestSigned());
        metadata.setRequireLogoutResponseSigned(extendedMetadata.isRequireLogoutResponseSigned());
        metadata.setEncryptionKey(extendedMetadata.getEncryptionKey());
        metadata.setSigningKey(extendedMetadata.getSigningKey());
        metadata.setTlsKey(extendedMetadata.getTlsKey());

        ModelAndView model = new ModelAndView(new InternalResourceView("/WEB-INF/security/metadataView.jsp", true));
        model.addObject("metadata", metadata);
        model.addObject("storagePath", fileName);

        return model;

    }

    protected String getMetadataAsString(EntityDescriptor descriptor) throws MarshallingException {

        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(descriptor);
        Element element = marshaller.marshall(descriptor);
        return XMLHelper.nodeToString(element);

    }

    protected String getBaseURL(HttpServletRequest request) {

        StringBuffer sb = new StringBuffer();
        sb.append(request.getScheme()).append("://").append(request.getServerName()).append(":").append(request.getServerPort());
        sb.append(request.getContextPath());

        String baseURL = sb.toString();
        log.debug("Base URL {}", baseURL);
        return baseURL;

    }

    protected String getEntityId(HttpServletRequest request) {
        log.debug("Server name used as entity id {}", request.getServerName());
        return request.getServerName();
    }

    protected Map<String, String> getAvailablePrivateKeys() throws KeyStoreException {
        Map<String, String> availableKeys = new HashMap<String, String>();
        Set<String> aliases = keyManager.getAvailableCredentials();
        for (String key : aliases) {
            try {
                log.debug("Found key {}", key);
                Credential credential = keyManager.getCredential(key);
                if (credential.getPrivateKey() != null) {
                    log.debug("Adding private key with alias {} and entityID {}", key, credential.getEntityId());
                    availableKeys.put(key, key + " (" + credential.getEntityId() + ")");
                }
            } catch (Exception e) {
                log.debug("Error loading key", e);
            }
        }
        return availableKeys;
    }

    protected String getFileName(EntityDescriptor entityDescriptor) {
        StringBuilder fileName = new StringBuilder();
        for (Character c : entityDescriptor.getEntityID().toCharArray()) {
            if (Character.isJavaIdentifierPart(c)) {
                fileName.append(c);
            }
        }
        if (fileName.length() > 0) {
            fileName.append("_sp.xml");
            return fileName.toString();
        } else {
            return "default_sp.xml";
        }
    }

    protected String getConfiguration(String fileName, ExtendedMetadata metadata) {
        StringBuilder sb = new StringBuilder();
        sb.append("<bean class=\"org.springframework.security.saml.metadata.ExtendedMetadataDelegate\">\n" +
                "    <constructor-arg>\n" +
                "        <bean class=\"org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider\">\n" +
                "            <constructor-arg>\n" +
                "                <value type=\"java.io.File\">classpath:security/").append(fileName).append("</value>\n" +
                "            </constructor-arg>\n" +
                "            <property name=\"parserPool\" ref=\"parserPool\"/>\n" +
                "        </bean>\n" +
                "    </constructor-arg>\n" +
                "    <constructor-arg>\n" +
                "        <bean class=\"org.springframework.security.saml.metadata.ExtendedMetadata\">\n" +
                "           <property name=\"local\" value=\"true\"/>\n" +
                "           <property name=\"alias\" value=\"").append(metadata.getAlias()).append("\"/>\n" +
                "           <property name=\"securityProfile\" value=\"").append(metadata.getSecurityProfile()).append("\"/>\n" +
                "           <property name=\"signingKey\" value=\"").append(metadata.getSigningKey()).append("\"/>\n" +
                "           <property name=\"encryptionKey\" value=\"").append(metadata.getEncryptionKey()).append("\"/>\n" +
                "           <property name=\"tlsKey\" value=\"").append(metadata.getTlsKey()).append("\"/>\n" +
                "           <property name=\"requireArtifactResolveSigned\" value=\"").append(metadata.isRequireArtifactResolveSigned()).append("\"/>\n" +
                "           <property name=\"requireLogoutRequestSigned\" value=\"").append(metadata.isRequireLogoutRequestSigned()).append("\"/>\n" +
                "           <property name=\"requireLogoutResponseSigned\" value=\"").append(metadata.isRequireLogoutResponseSigned()).append("\"/>\n" +
                "        </bean>\n" +
                "    </constructor-arg>\n" +
                "</bean>");
        return sb.toString();
    }

}