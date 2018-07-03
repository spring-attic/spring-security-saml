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
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A SamlMessageHandler is an object that can process incoming
 * SAML messages and produce responses.
 * A handler can be selective about what type of messages it can handle
 * by implementing the {@link #supports(HttpServletRequest)} method.
 */
public interface SamlMessageHandler {

	enum ProcessingStatus {
		STOP,
		STOP_HANDLERS,
		CONTINUE
	}

	/**
	 * Processes a SAML message an potentially produces a response.
	 * @param request - the incoming HTTP request
	 * @param response - the outgoing HTTP response
	 * @return - processing status as defined
	 * <ul>
	 *     <li>STOP - stop processing handlers and filters. Response is complete.</li>
	 *     <li>STOP_HANDLERS - stop processing handlers, continue down the filter chain</li>
	 *     <li>CONTINUE - continue processing handlers and filters in the filter chain</li>
	 * </ul>
	 * @throws IOException - per servlet specification
	 * {@link javax.servlet.Filter#doFilter(ServletRequest, ServletResponse, FilterChain)}
	 * @throws ServletException - per servlet specification
	 * {@link javax.servlet.Filter#doFilter(ServletRequest, ServletResponse, FilterChain)}
	 */
	ProcessingStatus process(HttpServletRequest request, HttpServletResponse response)
		throws IOException, ServletException;

	/**
	 * returns true if the the {@link #process(HttpServletRequest, HttpServletResponse)} method
	 * should be invoked.
	 * @param request - the incoming request
	 * @return true for the {@link #process(HttpServletRequest, HttpServletResponse)} method to be invoked.
	 *
	 */
	boolean supports(HttpServletRequest request);
}
