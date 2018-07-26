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
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlMessageHandler.ProcessingStatus;

import static org.springframework.security.saml.SamlMessageHandler.ProcessingStatus.STOP;
import static org.springframework.security.saml.SamlMessageHandler.ProcessingStatus.STOP_HANDLERS;

/**
 * Simple filter that handles all SAML messages.
 * No filter mapping is required as each handler will determine if the message
 * is a SAML message based on metadata preferences.
 * For performance optimization under default configurations it's wise to configure this filter
 * with the <code>/saml</code> mapping.
 */
public class SamlProcessingFilter implements Filter {

	private List<SamlMessageHandler> handlers = new LinkedList<>();
	private SamlErrorHandler errorHandler = null;

	public List<SamlMessageHandler> getHandlers() {
		return Collections.unmodifiableList(handlers);
	}

	public SamlProcessingFilter setHandlers(List<SamlMessageHandler> handlers) {
		this.handlers = new LinkedList<>(handlers);
		return this;
	}

	public SamlErrorHandler getErrorHandler() {
		return errorHandler;
	}

	public SamlProcessingFilter setErrorHandler(SamlErrorHandler errorHandler) {
		this.errorHandler = errorHandler;
		return this;
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
		throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse)resp;
		for (SamlMessageHandler p : handlers) {
			if (p.supports(request)) {
				try {
					ProcessingStatus status = p.process(request, response);
					if (status == STOP) {
						return;
					}
					else if (status == STOP_HANDLERS) {
						break;
					}
				} catch (Exception x) {
					SamlException root = x instanceof SamlException ?
						(SamlException)x :
						new SamlException(x);
					handleError(root, p, request, response);
					return; //stop everything
				}
			}
		}
		chain.doFilter(request, response);
	}

	protected void handleError(SamlException x,
							   SamlMessageHandler p,
							   HttpServletRequest request,
							   HttpServletResponse response) {
		if (getErrorHandler() != null ) {
			getErrorHandler().handle(x, p, request, response);
		}
		else {
			throw x;
		}
	}

	@Override
	public void destroy() {
	}
}
