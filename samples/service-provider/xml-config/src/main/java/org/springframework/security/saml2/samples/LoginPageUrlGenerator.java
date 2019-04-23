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

package org.springframework.security.saml2.samples;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.saml2.registration.HostedSaml2ServiceProviderRegistration;
import org.springframework.web.util.UriUtils;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.security.saml2.util.Saml2StringUtils.stripSlashes;

public class LoginPageUrlGenerator {

	private final HostedSaml2ServiceProviderRegistration configuration;

	public LoginPageUrlGenerator(HostedSaml2ServiceProviderRegistration configuration) {
		this.configuration = configuration;
	}

	public Map<String, String> getStaticLoginUrls() {
		Map<String, String> providerUrls = new HashMap<>();
		configuration.getProviders().stream().forEach(
			p -> {
				String linkText = p.getLinktext();
				String url = "/" +
					stripSlashes(configuration.getPathPrefix()) +
					"/authenticate/" +
					UriUtils.encode(p.getAlias(), UTF_8.toString());
				providerUrls.put(linkText, url);

			}
		);
		return providerUrls;
	}
}
