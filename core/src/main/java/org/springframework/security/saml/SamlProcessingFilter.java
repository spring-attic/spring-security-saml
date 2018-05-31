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

import org.springframework.security.saml.SamlMessageProcessor.ProcessingStatus;

import static org.springframework.security.saml.SamlMessageProcessor.ProcessingStatus.STOP;
import static org.springframework.security.saml.SamlMessageProcessor.ProcessingStatus.STOP_PROCESSORS;

public class SamlProcessingFilter implements Filter {

	private List<SamlMessageProcessor> processors = new LinkedList<>();

	public List<SamlMessageProcessor> getProcessors() {
		return processors;
	}

	public SamlProcessingFilter setProcessors(List<SamlMessageProcessor> processors) {
		this.processors = processors;
		return this;
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {

	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse response, FilterChain chain) throws
																						  IOException,
																						  ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		for (SamlMessageProcessor p : processors) {
			if (p.supports(request)) {
				ProcessingStatus status = p.process(request, (HttpServletResponse) response);
				if (status == STOP) {
					return;
				}
				else if (status == STOP_PROCESSORS) {
					break;
				}
			}
		}
		chain.doFilter(request, response);
	}

	@Override
	public void destroy() {

	}
}
