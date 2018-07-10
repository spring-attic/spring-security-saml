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
import java.io.StringWriter;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlMessageHandler;
import org.springframework.security.saml.SamlObjectResolver;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.config.LocalProviderConfiguration;
import org.springframework.security.saml.config.SamlServerConfiguration;
import org.springframework.security.saml.util.Network;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.HttpHeaders.CACHE_CONTROL;
import static org.springframework.http.HttpHeaders.PRAGMA;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.security.saml.util.StringUtils.addAliasPath;
import static org.springframework.security.saml.util.StringUtils.appendSlash;
import static org.springframework.security.saml.util.StringUtils.prependSlash;
import static org.springframework.security.saml.util.StringUtils.stripEndingSlases;
import static org.springframework.security.saml.util.StringUtils.stripSlashes;

public abstract class DefaultSamlMessageHandler<T extends DefaultSamlMessageHandler> implements SamlMessageHandler {


	protected final Log logger = LogFactory.getLog(getClass());


	private SamlServerConfiguration configuration;
	private SamlObjectResolver resolver;
	private SamlTransformer transformer;
	private Network network;
	private Defaults defaults;
	private SamlTemplateEngine samlTemplateEngine;
	private String forwardUrl = null;
	private boolean matchAgainstAliasPath;

	public SamlServerConfiguration getConfiguration() {
		return configuration;
	}

	public T setConfiguration(SamlServerConfiguration configuration) {
		this.configuration = configuration;
		return _this();
	}

	public boolean isMatchAgainstAliasPath() {
		return matchAgainstAliasPath;
	}

	public T setMatchAgainstAliasPath(boolean matchAgainstAliasPath) {
		this.matchAgainstAliasPath = matchAgainstAliasPath;
		return _this();
	}

	@SuppressWarnings("checked")
	protected T _this() {
		return (T) this;
	}

	public SamlObjectResolver getResolver() {
		return resolver;
	}

	public T setResolver(SamlObjectResolver resolver) {
		this.resolver = resolver;
		return _this();
	}

	public SamlTransformer getTransformer() {
		return transformer;
	}

	public T setTransformer(SamlTransformer transformer) {
		this.transformer = transformer;
		return _this();
	}

	public Network getNetwork() {
		return network;
	}

	public T setNetwork(Network network) {
		this.network = network;
		return _this();
	}

	public Defaults getDefaults() {
		return defaults;
	}

	public T setDefaults(Defaults defaults) {
		this.defaults = defaults;
		return _this();
	}

	public String getForwardUrl() {
		return forwardUrl;
	}

	public T setForwardUrl(String forwardUrl) {
		this.forwardUrl = forwardUrl;
		return _this();
	}

	protected boolean isUrlMatch(HttpServletRequest request, String path) {
		path = prependSlash(path);
		AntPathRequestMatcher matcher = new AntPathRequestMatcher(path);
		return isUrlMatch(request, matcher);
	}

	protected boolean isUrlMatch(HttpServletRequest request, AntPathRequestMatcher matcher) {
		return matcher.matches(request);
	}

	protected void processHtml(HttpServletRequest request,
							   HttpServletResponse response,
							   String html,
							   Map<String, String> model) {
		response.setHeader(CACHE_CONTROL, "no-cache, no-store");
		response.setHeader(PRAGMA, "no-cache");
		response.setContentType(TEXT_HTML_VALUE);
		response.setCharacterEncoding(UTF_8.name());
		StringWriter out = new StringWriter();
		getSamlTemplateEngine().process(
			request,
			html,
			model,
			out
		);
		try {
			response.getWriter().write(out.toString());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public SamlTemplateEngine getSamlTemplateEngine() {
		return samlTemplateEngine;
	}

	public T setSamlTemplateEngine(SamlTemplateEngine samlTemplateEngine) {
		this.samlTemplateEngine = samlTemplateEngine;
		return _this();
	}

	public abstract boolean supports(HttpServletRequest request);

	protected String getExpectedPath(LocalProviderConfiguration provider, String path) {
		String prefix = provider.getPrefix();
		String result = "/" + stripSlashes(prefix);
		result = stripEndingSlases(result) + "/" + stripSlashes(path);
		if (isMatchAgainstAliasPath()) {
			result = appendSlash(result);
			result = addAliasPath(result, provider.getAlias());
		}
		result = result + "/**";
		return result;
	}


}
