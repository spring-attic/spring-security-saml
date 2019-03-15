/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.provider;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;

public class SamlLogoutSuccessHandler implements LogoutSuccessHandler {

	public enum LogoutStatus {
		SUCCESS,
		REDIRECT,
		NOT_COMPLETE
	}

	public static final String RUN_SUCCESS = SamlLogoutSuccessHandler.class.getName() + ".logout.success";

	private final List<LogoutHandler> delegates;
	private final LogoutSuccessHandler successHandler;

	SamlLogoutSuccessHandler(LogoutSuccessHandler successHandler,
							 LogoutHandler... delegates) {

		this.successHandler = ofNullable(successHandler).orElse(new SimpleUrlLogoutSuccessHandler());
		this.delegates = delegates == null ?
			emptyList() :
			new LinkedList<>(asList(delegates));
	}


	@Override
	public void onLogoutSuccess(HttpServletRequest request,
								HttpServletResponse response,
								Authentication authentication) throws IOException, ServletException {
		if (LogoutStatus.REDIRECT.equals(request.getAttribute(RUN_SUCCESS))) {
			for (LogoutHandler handler : ofNullable(delegates).orElse(emptyList())) {
				handler.logout(request, response, authentication);
			}
		}
		else if (LogoutStatus.SUCCESS.equals(request.getAttribute(RUN_SUCCESS))) {
			for (LogoutHandler handler : ofNullable(delegates).orElse(emptyList())) {
				handler.logout(request, response, authentication);
			}
			if (successHandler != null) {
				successHandler.onLogoutSuccess(request, response, authentication);
			}
		}

	}
}
