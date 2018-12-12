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

package org.springframework.security.saml.serviceprovider.web.filters;

import java.util.List;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml.provider.HostedProvider;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.web.util.UrlPathHelper;

public interface SamlFilter<T extends HostedProvider> {

	String SAML_REQUEST = SamlFilter.class.getName() + ".saml-request";
	String SAML_RESPONSE = SamlFilter.class.getName() + ".saml-response";
	String SAML_PROVIDER = SamlFilter.class.getName() + ".saml-provider";

	default String getEndpointPath(HttpServletRequest request) {
		return new UrlPathHelper().getPathWithinApplication(request);
	}

	default T getProvider(HttpServletRequest request) {
		return (T) request.getAttribute(SAML_PROVIDER);
	}

	default Saml2Object getSamlRequest(HttpServletRequest request) {
		return (Saml2Object) request.getAttribute(SAML_REQUEST);
	}

	default Saml2Object getSamlResponse(HttpServletRequest request) {
		return (Saml2Object) request.getAttribute(SAML_RESPONSE);
	}

	default Endpoint getPreferredEndpoint(List<Endpoint> endpoints,
								  Binding preferredBinding,
								  int preferredIndex) {
		if (endpoints == null || endpoints.isEmpty()) {
			return null;
		}
		List<Endpoint> eps = endpoints;
		Endpoint result = null;
		//find the preferred binding
		if (preferredBinding != null) {
			for (Endpoint e : eps) {
				if (preferredBinding == e.getBinding()) {
					result = e;
					break;
				}
			}
		}
		//find the configured index
		if (result == null) {
			for (Endpoint e : eps) {
				if (e.getIndex() == preferredIndex) {
					result = e;
					break;
				}
			}
		}
		//find the default endpoint
		if (result == null) {
			for (Endpoint e : eps) {
				if (e.isDefault()) {
					result = e;
					break;
				}
			}
		}
		//fallback to the very first available endpoint
		if (result == null) {
			result = eps.get(0);
		}
		return result;
	}

}
