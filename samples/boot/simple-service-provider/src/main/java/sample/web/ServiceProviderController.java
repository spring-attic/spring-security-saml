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
package sample.web;

import java.util.LinkedList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.SamlObjectResolver;
import org.springframework.security.saml.config.ExternalProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.util.Network;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import sample.config.AppConfig;

import static java.nio.charset.StandardCharsets.UTF_8;

@Controller
public class ServiceProviderController {

	private AppConfig configuration;
	private SamlObjectResolver resolver;
	private Network network;

	@Autowired
	public void setNetwork(Network network) {
		this.network = network;
	}

	@Autowired
	public void setAppConfig(AppConfig config) {
		this.configuration = config;
	}

	@Autowired
	public void setMetadataResolver(SamlObjectResolver resolver) {
		this.resolver = resolver;
	}

	@RequestMapping(value = {"/", "/index", "logged-in"})
	public String home() {
		return "logged-in";
	}

	@RequestMapping("/saml/sp/select")
	public String selectProvider(HttpServletRequest request, Model model) {
		List<ModelProvider> providers = new LinkedList<>();
		configuration.getServiceProvider().getProviders().stream().forEach(
			p -> {
				try {
					ModelProvider mp = new ModelProvider().setLinkText(p.getLinktext()).setRedirect(getDiscoveryRedirect(request, p));
					providers.add(mp);
				} catch (Exception x) {
					x.printStackTrace();
				}
			}
		);
		model.addAttribute("idps", providers);
		return "select-provider";
	}

	protected String getDiscoveryRedirect(HttpServletRequest request, ExternalProviderConfiguration p) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(network.getBasePath(request));
		builder.pathSegment("saml/sp/discovery");
		IdentityProviderMetadata metadata = resolver.resolveIdentityProvider(p);
		builder.queryParam("idp", UriUtils.encode(metadata.getEntityId(), UTF_8));
		return builder.build().toUriString();
	}
}
