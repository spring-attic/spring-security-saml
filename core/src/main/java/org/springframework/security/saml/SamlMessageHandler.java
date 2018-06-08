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

package org.springframework.security.saml;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.config.SamlServerConfiguration;
import org.springframework.security.saml.spi.Defaults;
import org.springframework.security.saml.util.Network;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.HttpHeaders.CACHE_CONTROL;
import static org.springframework.http.HttpHeaders.PRAGMA;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;

public abstract class SamlMessageHandler<T extends SamlMessageHandler> {

	public enum ProcessingStatus {
		STOP,
		STOP_HANDLERS,
		CONTINUE
	}

	private SamlServerConfiguration configuration;
	private SamlObjectResolver resolver;
	private SamlTransformer transformer;
	private Network network;
	private Defaults defaults;
	private SamlTemplateEngine samlTemplateEngine;
	private String forwardUrl = null;

	public SamlServerConfiguration getConfiguration() {
		return configuration;
	}

	public T setConfiguration(SamlServerConfiguration configuration) {
		this.configuration = configuration;
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

	protected abstract ProcessingStatus process(HttpServletRequest request, HttpServletResponse response)
		throws IOException, ServletException;

	protected boolean isUrlMatch(HttpServletRequest request, String path) {
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
			response,
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
}
