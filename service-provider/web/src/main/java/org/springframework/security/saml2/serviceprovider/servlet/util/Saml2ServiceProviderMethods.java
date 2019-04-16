/*
 * Copyright 2002-2019 the original author or authors.
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
 *
 */

package org.springframework.security.saml2.serviceprovider.servlet.util;

import java.util.List;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.model.Saml2Object;
import org.springframework.security.saml2.model.metadata.Saml2BindingType;
import org.springframework.security.saml2.model.metadata.Saml2Endpoint;
import org.springframework.security.saml2.provider.HostedSaml2ServiceProvider;
import org.springframework.security.saml2.provider.validation.Saml2ServiceProviderValidator;
import org.springframework.security.saml2.serviceprovider.Saml2ServiceProviderResolver;

public interface Saml2ServiceProviderMethods {

	Saml2Object getSamlRequest(HttpServletRequest request);

	Saml2Object parseSamlObject(HttpServletRequest request,
								HostedSaml2ServiceProvider provider,
								String parameterName);

	HostedSaml2ServiceProvider getProvider(HttpServletRequest request);

	Saml2Transformer getTransformer();

	Saml2ServiceProviderValidator getValidator();

	Saml2ServiceProviderResolver getResolver();

	Saml2Object getSamlResponse(HttpServletRequest request);

	Saml2Endpoint getPreferredEndpoint(List<Saml2Endpoint> endpoints,
									   Saml2BindingType preferredBinding,
									   int preferredIndex);

}
