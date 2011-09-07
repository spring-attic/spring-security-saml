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
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * The filter expects calls on configured URL and presents user with SAML2 metadata representing
 * this application deployment. In case the application is configured to automatically generate metadata,
 * the generation occurs upon first invocation of this filter (first request made to the server).
 *
 * @author Vladimir Schäfer
 */
public class MetadataGeneratorFilter extends GenericFilterBean {

    private final Log logger = LogFactory.getLog(this.getClass());

    /**
     * Class storing all SAML metadata documents
     */
    protected MetadataManager manager;

    /**
     * Class capable of generating new metadata.
     */
    protected MetadataGenerator generator;

    /**
     * Default alias for generated entities.
     */
    private static final String DEFAULT_ALIAS = "defaultAlias";

    /**
     * Default constructor.
     *
     * @param generator generator
     */
    public MetadataGeneratorFilter(MetadataGenerator generator) {
        this.generator = generator;
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        processMetadataInitialization((HttpServletRequest) request);
        chain.doFilter(request, response);
    }

    /**
     * Verifies whether generation is needed and if so the metadata document is created and stored in metadata
     * manager.
     *
     * @param request request
     * @throws javax.servlet.ServletException error
     */
    protected void processMetadataInitialization(HttpServletRequest request) throws ServletException {

        // In case the hosted SP metadata weren't initialized, let's do it now
        if (manager.getHostedSPName() == null) {

            synchronized (MetadataManager.class) {

                if (manager.getHostedSPName() == null) {

                    try {

                        logger.info("No default metadata configured, generating with default values, please pre-configure metadata for production use");

                        String alias = DEFAULT_ALIAS;

                        // Use default entityAlias if not set
                        if (generator.getEntityAlias() == null) {
                            generator.setEntityAlias(alias);
                        } else {
                            alias = generator.getEntityAlias();
                        }

                        // Use default baseURL if not set
                        if (generator.getEntityBaseURL() == null) {
                            generator.setEntityBaseURL(getDefaultBaseURL(request));
                        }

                        // Use default entityID if not set
                        if (generator.getEntityId() == null) {
                            generator.setEntityId(getDefaultEntityID(request, alias));
                        }

                        EntityDescriptor descriptor = generator.generateMetadata();
                        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
                        generator.generateExtendedMetadata(extendedMetadata);

                        logger.info("Created default metadata for system with entityID: " + descriptor.getEntityID());
                        MetadataMemoryProvider memoryProvider = new MetadataMemoryProvider(descriptor);
                        memoryProvider.initialize();
                        MetadataProvider metadataProvider = new ExtendedMetadataDelegate(memoryProvider, extendedMetadata);

                        manager.addMetadataProvider(metadataProvider);
                        manager.setHostedSPName(descriptor.getEntityID());
                        manager.refreshMetadata();

                    } catch (MetadataProviderException e) {
                        logger.error("Error generating system metadata", e);
                        throw new ServletException("Error generating system metadata", e);
                    }

                }

            }

        }

    }

    protected String getDefaultEntityID(HttpServletRequest request, String alias) {
        StringBuilder sb = new StringBuilder();
        sb.append(request.getScheme()).append("://").append(request.getServerName()).append(":").append(request.getServerPort());
        sb.append(request.getContextPath());
        sb.append(MetadataDisplayFilter.FILTER_URL + "/alias/");
        sb.append(alias);
        return sb.toString();
    }

    protected String getDefaultBaseURL(HttpServletRequest request) {
        StringBuilder sb = new StringBuilder();
        sb.append(request.getScheme()).append("://").append(request.getServerName()).append(":").append(request.getServerPort());
        sb.append(request.getContextPath());
        return sb.toString();
    }

    @Autowired
    public void setManager(MetadataManager manager) {
        this.manager = manager;
    }

    /**
     * Verifies that required entities were autowired or set.
     *
     * @throws javax.servlet.ServletException
     */
    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(generator, "Metadata generator");
        Assert.notNull(manager, "MetadataManager must be set");
    }

}