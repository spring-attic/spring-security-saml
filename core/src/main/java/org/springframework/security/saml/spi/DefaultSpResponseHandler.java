/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.spi;

import java.io.IOException;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.config.LocalServiceProviderConfiguration;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.validation.ValidationException;

import static org.springframework.http.HttpMethod.GET;

public class DefaultSpResponseHandler extends DefaultSamlMessageHandler<DefaultSpResponseHandler> {

    private SamlValidator validator;
    private AuthenticationManager authenticationManager;

    @Override
    public ProcessingStatus process(HttpServletRequest request,
                                    HttpServletResponse response) throws IOException {
        ServiceProviderMetadata local = getLocalServiceProvider(request);
        String resp = getResponseParameter(request);
        //receive assertion
        String xml = getResponseXml(request, resp);
        if (logger.isTraceEnabled()) {
            logger.trace("Received SAMLResponse:" + xml);
        }
        //extract basic data so we can map it to an IDP
        List<SimpleKey> localKeys = local.getServiceProvider().getKeys();
        Response r = getResponse(xml, localKeys, null);
        IdentityProviderMetadata identityProviderMetadata = getResolver().resolveIdentityProvider(r);
        //validate signature
        r = getResponse(xml, localKeys, identityProviderMetadata.getIdentityProvider().getKeys());

        ValidationException validation = validateResponse(request, r);
        if (validation != null) {
            return handleError(validation, request, response);
        } else {
            //extract the assertion
            try {
                authenticate(
                    request,
                    response,
                    r,
                    local.getEntityId(),
                    identityProviderMetadata.getEntityId()
                );
                return postAuthentication(request, response);
            } catch (AuthenticationException x) {
                return handleError(x, request, response);
            }
        }

    }

    protected ValidationException validateResponse(HttpServletRequest request, Response r) {
        try {
            getValidator().validate(r, getResolver(), request);
            return null;
        } catch (ValidationException x) {
            return x;
        }
    }

    protected Response getResponse(String xml, List<SimpleKey> localKeys, List<SimpleKey> verificationKKeys) {
        return (Response) getTransformer().fromXml(xml, verificationKKeys, localKeys);
    }

    protected String getResponseXml(HttpServletRequest request, String resp) {
        return getTransformer().samlDecode(resp, GET.matches(request.getMethod()));
    }

    protected String getResponseParameter(HttpServletRequest request) {
        return request.getParameter("SAMLResponse");
    }

    @Override
    public boolean supports(HttpServletRequest request) {
        LocalServiceProviderConfiguration sp = getConfiguration().getServiceProvider();

        String path = getExpectedPath(sp, "SSO");
        return isUrlMatch(request, path) && getResponseParameter(request) != null;
    }

    protected void authenticate(HttpServletRequest request,
                                HttpServletResponse response,
                                Response samlResponse,
                                String spEntityId,
                                String idpEntityId) {
        Authentication authentication = new DefaultSamlAuthentication(
            true,
            samlResponse.getAssertions().get(0),
            idpEntityId,
            spEntityId,
            request.getParameter("RelayState")
        );
        if (authenticationManager != null) {
            authentication = authenticationManager.authenticate(authentication);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    protected ProcessingStatus postAuthentication(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
        response.sendRedirect(request.getContextPath() + "/");
        return ProcessingStatus.STOP;
    }

    public DefaultSpResponseHandler setValidator(SamlValidator validator) {
        this.validator = validator;
        return this;
    }

    public SamlValidator getValidator() {
        return validator;
    }

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public DefaultSpResponseHandler setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        return this;
    }

}
