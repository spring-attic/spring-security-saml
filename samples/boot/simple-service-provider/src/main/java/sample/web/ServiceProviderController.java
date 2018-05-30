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

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlObjectResolver;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.config.ExternalProviderConfiguration;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.util.Network;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import sample.config.AppConfig;

import static org.springframework.http.HttpMethod.GET;

@Controller
public class ServiceProviderController implements InitializingBean {

	private AppConfig configuration;
	private SamlTransformer transformer;
	private SamlObjectResolver resolver;
	private SamlValidator validator;
	private Network network;

	@Autowired
	public ServiceProviderController setNetwork(Network network) {
		this.network = network;
		return this;
	}

	@Autowired
	public void setValidator(SamlValidator validator) {
		this.validator = validator;
	}

	@Autowired
	public void setTransformer(SamlTransformer transformer) {
		this.transformer = transformer;
	}

	@Autowired
	public void setAppConfig(AppConfig config) {
		this.configuration = config;
	}

	@Override
	public void afterPropertiesSet() {
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
		builder.queryParam("idp", metadata.getEntityId());
		return builder.build().toUriString();
	}

	protected ServiceProviderMetadata getServiceProviderMetadata(HttpServletRequest request) {
		return getMetadataResolver().getLocalServiceProvider(network.getBasePath(request));
	}

	public SamlObjectResolver getMetadataResolver() {
		return resolver;
	}

	@Autowired
	public void setMetadataResolver(SamlObjectResolver resolver) {
		this.resolver = resolver;
	}

	@RequestMapping("/saml/sp/SSO")
	public View sso(HttpServletRequest request,
					@RequestParam(name = "SAMLResponse", required = true) String response,
					@RequestParam(name = "RelayState", required = false) String relay) {
		//receive assertion
		String xml = transformer.samlDecode(response, GET.matches(request.getMethod()));
		//extract basic data so we can map it to an IDP
		List<SimpleKey> localKeys = resolver
			.getLocalServiceProvider(network.getBasePath(request)).getServiceProvider().getKeys();
		Response r = (Response) transformer.fromXml(xml, null, localKeys);
		IdentityProviderMetadata identityProviderMetadata = resolver.resolveIdentityProvider(r);
		//validate signature
		r = (Response) transformer.fromXml(xml, identityProviderMetadata.getIdentityProvider().getKeys(), localKeys);
		//validate object
		validator.validate(r, resolver, request);
		//extract the assertion
		NameIdPrincipal principal = (NameIdPrincipal) r.getAssertions().get(0).getSubject().getPrincipal();
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(principal.getValue(), null, Collections.emptyList());
		SecurityContextHolder.getContext().setAuthentication(token);
		RedirectView view = new RedirectView("/");
		view.setContextRelative(true);
		return view;
	}
}
