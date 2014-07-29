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
package org.springframework.security.saml.context;

import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.SAMLCredential;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Implementation is supposed to provide SAMLContext by populating all data about the local entity related
 * to an Request.
 *
 * @author Vladimir Schaefer
 */
public interface SAMLContextProvider {

    /**
     * Creates a SAMLContext with local entity values filled. Also request and response must be stored in the context
     * as message transports. Local entity ID is populated from data in the request object.
     *
     * @param request request
     * @param response response
     * @return context
     * @throws MetadataProviderException in case of metadata problems
     */
    SAMLMessageContext getLocalEntity(HttpServletRequest request, HttpServletResponse response) throws MetadataProviderException;

    /**
     * Creates a SAMLContext with local entity and peer values filled. Also request and response must be stored in the context
     * as message transports. Local and peer entity IDs are populated from data in the request object.
     *
     * @param request request
     * @param response response
     * @return context
     * @throws MetadataProviderException in case of metadata problems
     */
    SAMLMessageContext getLocalAndPeerEntity(HttpServletRequest request, HttpServletResponse response) throws MetadataProviderException;

}
