/* Copyright 2009-2011 Vladimir Schäfer
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
package org.springframework.security.saml.metadata;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;
import org.w3c.dom.Element;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * The filter expects calls on configured URL and presents user with SAML2 metadata representing
 * this application deployment. In case the application is configured to automatically generate metadata,
 * the generation occurs upon first invocation of this filter (first request made to the server).
 *
 * @author Vladimir Schäfer
 */
public class MetadataDisplayFilter extends GenericFilterBean {

    private final Log logger = LogFactory.getLog(this.getClass());

    /**
     * Class storing all SAML metadata documents
     */
    protected MetadataManager manager;

    /**
     * Provider for context based on URL
     */
    protected SAMLContextProvider contextProvider;

    /**
     * Default name of path suffix which will invoke this filter.
     */
    public static final String FILTER_URL = "/saml/metadata";

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        FilterInvocation fi = new FilterInvocation(request, response, chain);

        if (!processFilter(fi.getRequest())) {
            chain.doFilter(request, response);
            return;
        }

        processMetadataDisplay(fi.getRequest(), fi.getResponse());

    }

    /**
     * The filter will be used in case the URL of the request contains the FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     * @return true if this filter should be used
     */
    protected boolean processFilter(HttpServletRequest request) {
        return SAMLUtil.processFilter(FILTER_URL, request);
    }

    /**
     * The filter attempts to generate application metadata (if configured so) and in case the call is made
     * to the expected URL the metadata value is displayed and no further filters are invoked. Otherwise
     * filter chain invocation continues.
     *
     * @param request  request
     * @param response response
     * @throws javax.servlet.ServletException error
     * @throws java.io.IOException            io error
     */
    protected void processMetadataDisplay(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        try {
            SAMLMessageContext context = contextProvider.getLocalEntity(request, response);
            String entityId = context.getLocalEntityId();
            response.setContentType("application/samlmetadata+xml"); // SAML_Meta, 4.1.1 - line 1235
            displayMetadata(entityId, response.getWriter());
        } catch (MetadataProviderException e) {
            throw new ServletException("Error initializing metadata", e);
        }
    }

    /**
     * Method writes metadata document into given writer object.
     *
     * @param spEntityName id of entity to display metadata for
     * @param writer       output for metadata
     * @throws ServletException error retrieving or writing the metadata
     */
    protected void displayMetadata(String spEntityName, PrintWriter writer) throws ServletException {
        try {
            EntityDescriptor descriptor = manager.getEntityDescriptor(spEntityName);
            if (descriptor == null) {
                throw new ServletException("Metadata entity with ID " + manager.getHostedSPName() + " wasn't found");
            } else {
                MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
                Marshaller marshaller = marshallerFactory.getMarshaller(descriptor);
                Element element = marshaller.marshall(descriptor);
                writer.print(XMLHelper.nodeToString(element));
            }
        } catch (MarshallingException e) {
            logger.error("Error marshalling entity descriptor", e);
            throw new ServletException(e);
        } catch (MetadataProviderException e) {
            logger.error("Error retrieving metadata", e);
            throw new ServletException("Error retrieving metadata", e);
        }
    }

    @Autowired
    public void setManager(MetadataManager manager) {
        this.manager = manager;
    }

    @Autowired
    public void setContextProvider(SAMLContextProvider contextProvider) {
        this.contextProvider = contextProvider;
    }

    /**
     * Verifies that required entities were autowired or set.
     *
     * @throws ServletException
     */
    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(manager, "MetadataManager must be set");
        Assert.notNull(contextProvider, "Context provider must be set");
    }

}