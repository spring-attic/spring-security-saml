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
package org.springframework.security.saml.metadata;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.annotation.Required;
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
    private MetadataManager manager;

    /**
     * Enables creation of metadata corresponding to the current deployment
     */
    private MetadataGenerator generator;

    /**
     * The URL processed by this filter must end with this suffix in order to be processed.
     */
    private static final String DEFAULT_FILTER_URL = "saml/metadata";

    /**
     * User configured path which overrides the default value.
     */
    private String filterSuffix;

    /**
     * The filter will be used in case the URL of the request ends with DEFAULT_FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     *
     * @return true if this filter should be used
     */
    protected boolean processFilter(HttpServletRequest request) {
        if (filterSuffix != null) {
            return (request.getRequestURI().endsWith(filterSuffix));
        } else {
            return (request.getRequestURI().endsWith(DEFAULT_FILTER_URL));
        }
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilterHttp((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    /**
     * The filter attempts to generate application metadata (if configured so) and in case the call is made
     * to the expected URL the metadata value is displayed and no further filters are invoked. Otherwise
     * filterchain invocation continues.
     */
    protected void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        initializeSystemMetadata(request);
        if (!processFilter(request)) {
            chain.doFilter(request, response);
        } else {
            displayMetadata(response.getWriter());
        }
    }

    /**
     * Method writes metadata document into given writer object.
     *
     * @param writer output for metadata
     *
     * @throws ServletException error retrieving or writing the metadata
     */
    protected void displayMetadata(PrintWriter writer) throws ServletException {
        try {
            String spEntityName = manager.getHostedSPName();
            EntityDescriptor descriptor = manager.getEntityDescriptor(spEntityName);
            if (descriptor == null) {
                throw new ServletException("Metadata entity with ID " + manager.getHostedSPName() + " wasn't found");
            } else {
                MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
                Marshaller marshaller = marshallerFactory.getMarshaller(descriptor);
                Element element = marshaller.marshall(descriptor);
                writer.print(XMLHelper.prettyPrintXML(element));
            }
        } catch (MarshallingException e) {
            logger.error("Error marshalling entity descriptor", e);
            throw new ServletException(e);
        } catch (MetadataProviderException e) {
            logger.error("Error retrieving metadata", e);
            throw new ServletException("Error retrieving metadata", e);
        }
    }

    /**
     * Verifies whether generation is needed and if so the metadata document is created and stored in metadata
     * manager.
     *
     * @param request request
     *
     * @throws ServletException error
     */
    protected void initializeSystemMetadata(HttpServletRequest request) throws ServletException {
        // In case the hosted SP metadata weren't initialized, let's do it now
        if (manager.getHostedSPName() == null) {
            synchronized (MetadataManager.class) {
                if (manager.getHostedSPName() == null) {
                    try {
                        // Use default if not set
                        if (generator.getEntityPath() == null) {
                            generator.setEntityPath(getEntityID(request));
                        }
                        EntityDescriptor descriptor = generator.generateMetadata();
                        logger.info("Created metadata for system with ID: " + descriptor.getEntityID());
                        MetadataProvider metadataProvider = new MetadataMemoryProvider(descriptor);
                        manager.addMetadataProvider(metadataProvider);
                        manager.setHostedSPName(descriptor.getEntityID());
                    } catch (MetadataProviderException e) {
                        logger.error("Error generating system metadata", e);
                        throw new ServletException("Error generating system metadata", e);
                    }
                }
            }
        }
    }

    protected String getEntityID(HttpServletRequest request) {
        StringBuffer sb = new StringBuffer();
        sb.append(request.getScheme()).append("://").append(request.getServerName());
        sb.append(":").append(request.getServerPort()).append(request.getContextPath());
        return sb.toString();
    }

    public String getFilterSuffix() {
        return filterSuffix;
    }

    public void setFilterSuffix(String filterSuffix) {
        this.filterSuffix = filterSuffix;
    }

    @Required
    public void setManager(MetadataManager manager) {
        this.manager = manager;
    }

    @Required
    public void setGenerator(MetadataGenerator generator) {
        this.generator = generator;
    }
    
}