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

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.InternalResourceView;

import javax.servlet.http.HttpServletRequest;
import java.security.KeyStoreException;
import java.util.*;

import static org.springframework.util.StringUtils.hasLength;

/**
 * Class allows manipulation of metadata from web UI.
 */
@Controller
@RequestMapping("/metadata")
public class MetadataController {

    private final Logger log = LoggerFactory.getLogger(MetadataController.class);

    public static enum AllowedSSOBindings {
        SSO_POST, SSO_PAOS, SSO_ARTIFACT, HOKSSO_POST, HOKSSO_ARTIFACT
    }

    @Autowired
    MetadataManager metadataManager;

    @Autowired
    KeyManager keyManager;

    @RequestMapping
    public ModelAndView metadataList() throws MetadataProviderException {

        ModelAndView model = new ModelAndView(new InternalResourceView("/WEB-INF/security/metadataList.jsp", true));

        model.addObject("hostedSP", metadataManager.getHostedSPName());
        model.addObject("spList", metadataManager.getSPEntityNames());
        model.addObject("idpList", metadataManager.getIDPEntityNames());
        model.addObject("metadata", metadataManager.getAvailableProviders());

        return model;

    }

    @RequestMapping(value = "/login")
    public ModelAndView adminLogin() {

        ModelAndView model = new ModelAndView(new InternalResourceView("/WEB-INF/security/adminLogin.jsp", true));
        return model;

    }

    @RequestMapping(value = "/refresh")
    public ModelAndView refreshMetadata() throws MetadataProviderException {

        metadataManager.refreshMetadata();
        return metadataList();

    }

    @RequestMapping(value = "/provider")
    public ModelAndView displayProvider(@RequestParam("providerIndex") int providerIndex) {

        ModelAndView model = new ModelAndView(new InternalResourceView("/WEB-INF/security/providerView.jsp", true));
        ExtendedMetadataDelegate delegate = metadataManager.getAvailableProviders().get(providerIndex);
        model.addObject("provider", delegate);
        model.addObject("providerIndex", providerIndex);
        return model;

    }

    @RequestMapping(value = "/removeProvider")
    public ModelAndView removeProvider(@RequestParam int providerIndex) throws MetadataProviderException {

        ExtendedMetadataDelegate delegate = metadataManager.getAvailableProviders().get(providerIndex);
        metadataManager.removeMetadataProvider(delegate);
        return metadataList();

    }

    @RequestMapping(value = "/generate")
    public ModelAndView generateMetadata(HttpServletRequest request) throws KeyStoreException {

        ModelAndView model = new ModelAndView(new InternalResourceView("/WEB-INF/security/metadataGenerator.jsp", true));
        MetadataForm defaultForm = new MetadataForm();

        model.addObject("availableKeys", getAvailablePrivateKeys());
        defaultForm.setBaseURL(getBaseURL(request));
        defaultForm.setEntityId(getEntityId(request));
        defaultForm.setNameID(MetadataGenerator.defaultNameID.toArray(new String[MetadataGenerator.defaultNameID.size()]));

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

        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        MetadataGenerator generator = new MetadataGenerator();
        generator.setKeyManager(keyManager);
        generator.setExtendedMetadata(extendedMetadata);

        // Basic metadata properties
        generator.setEntityId(metadata.getEntityId());
        generator.setEntityBaseURL(metadata.getBaseURL());
        generator.setRequestSigned(metadata.isRequestSigned());
        generator.setWantAssertionSigned(metadata.isWantAssertionSigned());

        Collection<String> bindingsSSO = new LinkedList<String>();
        Collection<String> bindingsHoKSSO = new LinkedList<String>();
        String defaultBinding = metadata.getSsoDefaultBinding();
        int assertionConsumerIndex = 0;

        // Set default and included bindings
        for (String binding : metadata.getSsoBindings()) {
            if (binding.equalsIgnoreCase(defaultBinding)) {
                assertionConsumerIndex = bindingsSSO.size() + bindingsHoKSSO.size();
            }
            if (AllowedSSOBindings.SSO_POST.toString().equalsIgnoreCase(binding)) {
                bindingsSSO.add(SAMLConstants.SAML2_POST_BINDING_URI);
            } else if (AllowedSSOBindings.SSO_ARTIFACT.toString().equalsIgnoreCase(binding)) {
                bindingsSSO.add(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
            } else if (AllowedSSOBindings.SSO_PAOS.toString().equalsIgnoreCase(binding)) {
                bindingsSSO.add(SAMLConstants.SAML2_PAOS_BINDING_URI);
            } else if (AllowedSSOBindings.HOKSSO_POST.toString().equalsIgnoreCase(binding)) {
                bindingsHoKSSO.add(SAMLConstants.SAML2_POST_BINDING_URI);
            } else if (AllowedSSOBindings.HOKSSO_ARTIFACT.toString().equalsIgnoreCase(binding)) {
                bindingsHoKSSO.add(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
            }
        }

        // Set bindings
        generator.setBindingsSSO(bindingsSSO);
        generator.setBindingsHoKSSO(bindingsHoKSSO);
        generator.setAssertionConsumerIndex(assertionConsumerIndex);

        // Name IDs
        generator.setNameID(Arrays.asList(metadata.getNameID()));

        // Keys
        extendedMetadata.setSigningKey(metadata.getSigningKey());
        extendedMetadata.setEncryptionKey(metadata.getEncryptionKey());
        if (hasLength(metadata.getTlsKey())) {
            extendedMetadata.setTlsKey(metadata.getTlsKey());
        }

        // Discovery
        if (metadata.isIncludeDiscovery()) {
            extendedMetadata.setIdpDiscoveryEnabled(true);
            generator.setIncludeDiscoveryExtension(metadata.isIncludeDiscoveryExtension());
            if (metadata.getCustomDiscoveryURL() != null && metadata.getCustomDiscoveryURL().length() > 0) {
                extendedMetadata.setIdpDiscoveryURL(metadata.getCustomDiscoveryURL());
            }
            if (metadata.getCustomDiscoveryResponseURL() != null && metadata.getCustomDiscoveryResponseURL().length() > 0) {
                extendedMetadata.setIdpDiscoveryResponseURL(metadata.getCustomDiscoveryResponseURL());
            }
        } else {
            extendedMetadata.setIdpDiscoveryEnabled(false);
            generator.setIncludeDiscoveryExtension(false);
        }

        // Alias
        if (hasLength(metadata.getAlias())) {
            extendedMetadata.setAlias(metadata.getAlias());
        }

        // Security settings
        extendedMetadata.setSecurityProfile(metadata.getSecurityProfile());
        extendedMetadata.setSslSecurityProfile(metadata.getSslSecurityProfile());
        extendedMetadata.setRequireLogoutRequestSigned(metadata.isRequireLogoutRequestSigned());
        extendedMetadata.setRequireLogoutResponseSigned(metadata.isRequireLogoutResponseSigned());
        extendedMetadata.setRequireArtifactResolveSigned(metadata.isRequireArtifactResolveSigned());
        extendedMetadata.setSslHostnameVerification(metadata.getSslHostnameVerification());

        // Metadata signing
        extendedMetadata.setSignMetadata(metadata.isSignMetadata());
        if (hasLength(metadata.getSigningAlgorithm())) {
            extendedMetadata.setSigningAlgorithm(metadata.getSigningAlgorithm());
        }

        // Generate values
        EntityDescriptor generatedDescriptor = generator.generateMetadata();
        ExtendedMetadata generatedExtendedMetadata = generator.generateExtendedMetadata();

        if (metadata.isStore()) {

            MetadataMemoryProvider memoryProvider = new MetadataMemoryProvider(generatedDescriptor);
            memoryProvider.initialize();
            MetadataProvider metadataProvider = new ExtendedMetadataDelegate(memoryProvider, generatedExtendedMetadata);
            metadataManager.addMetadataProvider(metadataProvider);
            metadataManager.setHostedSPName(generatedDescriptor.getEntityID());
            metadataManager.setRefreshRequired(true);
            metadataManager.refreshMetadata();

        }

        return displayMetadata(generatedDescriptor, generatedExtendedMetadata);

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
        metadata.setSslSecurityProfile(extendedMetadata.getSslSecurityProfile());
        metadata.setSerializedMetadata(getMetadataAsString(entityDescriptor, extendedMetadata));
        metadata.setConfiguration(getConfiguration(fileName, extendedMetadata));
        metadata.setEntityId(entityDescriptor.getEntityID());
        metadata.setAlias(extendedMetadata.getAlias());
        metadata.setRequireArtifactResolveSigned(extendedMetadata.isRequireArtifactResolveSigned());
        metadata.setRequireLogoutRequestSigned(extendedMetadata.isRequireLogoutRequestSigned());
        metadata.setRequireLogoutResponseSigned(extendedMetadata.isRequireLogoutResponseSigned());
        metadata.setEncryptionKey(extendedMetadata.getEncryptionKey());
        metadata.setSigningKey(extendedMetadata.getSigningKey());
        metadata.setTlsKey(extendedMetadata.getTlsKey());
        metadata.setSslHostnameVerification(extendedMetadata.getSslHostnameVerification());

        metadata.setSignMetadata(extendedMetadata.isSignMetadata());
        metadata.setSigningAlgorithm(extendedMetadata.getSigningAlgorithm());

        metadata.setIncludeDiscovery(extendedMetadata.isIdpDiscoveryEnabled());
        metadata.setCustomDiscoveryURL(extendedMetadata.getIdpDiscoveryResponseURL());
        metadata.setCustomDiscoveryResponseURL(extendedMetadata.getIdpDiscoveryURL());

        // TODO other fields nameIDs

        ModelAndView model = new ModelAndView(new InternalResourceView("/WEB-INF/security/metadataView.jsp", true));
        model.addObject("metadata", metadata);
        model.addObject("storagePath", fileName);

        return model;

    }

    protected String getMetadataAsString(EntityDescriptor descriptor, ExtendedMetadata extendedMetadata) throws MarshallingException {
        return SAMLUtil.getMetadataAsString(metadataManager, keyManager, descriptor, extendedMetadata);
    }

    protected String getBaseURL(HttpServletRequest request) {

        String baseURL = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
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
                "        <bean class=\"org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider\">\n" +
                "            <constructor-arg>\n" +
                "                <bean class=\"java.util.Timer\"/>\n" +
                "            </constructor-arg>\n" +
                "            <constructor-arg>\n" +
                "                <bean class=\"org.opensaml.util.resource.ClasspathResource\">\n" +
                "                    <constructor-arg value=\"/metadata/").append(fileName).append("\"/>\n" +
                "                </bean>\n" +
                "            </constructor-arg>\n" +
                "            <property name=\"parserPool\" ref=\"parserPool\"/>\n" +
                "        </bean>\n" +
                "    </constructor-arg>\n" +
                "    <constructor-arg>\n" +
                "        <bean class=\"org.springframework.security.saml.metadata.ExtendedMetadata\">\n" +
                "           <property name=\"local\" value=\"true\"/>\n");
        if (metadata.getAlias() != null) {
            sb.append("           <property name=\"alias\" value=\"").append(metadata.getAlias()).append("\"/>\n");
        }
        sb.append("           <property name=\"securityProfile\" value=\"").append(metadata.getSecurityProfile()).append("\"/>\n" +
                "           <property name=\"sslSecurityProfile\" value=\"").append(metadata.getSslSecurityProfile()).append("\"/>\n" +
                "           <property name=\"sslHostnameVerification\" value=\"").append(metadata.getSslHostnameVerification()).append("\"/>\n" +
                "           <property name=\"signMetadata\" value=\"").append(metadata.isSignMetadata()).append("\"/>\n" +
                "           <property name=\"signingKey\" value=\"").append(metadata.getSigningKey()).append("\"/>\n" +
                "           <property name=\"encryptionKey\" value=\"").append(metadata.getEncryptionKey()).append("\"/>\n");
        if (metadata.getTlsKey() != null) {
            sb.append("           <property name=\"tlsKey\" value=\"").append(metadata.getTlsKey()).append("\"/>\n");
        }
        if (metadata.getSigningAlgorithm() != null) {
            sb.append("           <property name=\"signingAlgorithm\" value=\"").append(metadata.getSigningAlgorithm()).append("\"/>\n");
        }
        sb.append("           <property name=\"requireArtifactResolveSigned\" value=\"").append(metadata.isRequireArtifactResolveSigned()).append("\"/>\n" +
                "           <property name=\"requireLogoutRequestSigned\" value=\"").append(metadata.isRequireLogoutRequestSigned()).append("\"/>\n" +
                "           <property name=\"requireLogoutResponseSigned\" value=\"").append(metadata.isRequireLogoutResponseSigned()).append("\"/>\n");
        sb.append("           <property name=\"idpDiscoveryEnabled\" value=\"").append(metadata.isIdpDiscoveryEnabled()).append("\"/>\n");
        if (metadata.isIdpDiscoveryEnabled()) {
            sb.append("           <property name=\"idpDiscoveryURL\" value=\"").append(metadata.getIdpDiscoveryURL()).append("\"/>\n" +
                    "           <property name=\"idpDiscoveryResponseURL\" value=\"").append(metadata.getIdpDiscoveryResponseURL()).append("\"/>\n");
        }
        sb.append("        </bean>\n" +
                "    </constructor-arg>\n" +
                "</bean>");
        return sb.toString();
    }

    @ModelAttribute(value = "tab")
    public String getTabName() {
        return "metadata";
    }

}