/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.saml2.model.metadata;

import java.util.LinkedList;
import java.util.List;

/**
 * Base class for SAML providers
 *
 * @param <T> return class for builder pattern
 */
public class SsoProvider<T extends SsoProvider<T>> extends Saml2Provider<T> {

	private List<Saml2Endpoint> artifactResolutionService = new LinkedList<>();
	private List<Saml2Endpoint> singleLogoutService = new LinkedList<>();
	private List<Saml2Endpoint> manageNameIDService = new LinkedList<>();
	private List<Saml2NameId> nameIds = new LinkedList<>();
	private Saml2Endpoint discovery;
	private Saml2Endpoint requestInitiation;

	public List<Saml2Endpoint> getArtifactResolutionService() {
		return artifactResolutionService;
	}

	public T setArtifactResolutionService(List<Saml2Endpoint> artifactResolutionService) {
		this.artifactResolutionService = artifactResolutionService;
		return _this();
	}

	public List<Saml2Endpoint> getSingleLogoutService() {
		return singleLogoutService;
	}

	public T setSingleLogoutService(List<Saml2Endpoint> singleLogoutService) {
		this.singleLogoutService = singleLogoutService;
		return _this();
	}

	public List<Saml2Endpoint> getManageNameIDService() {
		return manageNameIDService;
	}

	public T setManageNameIDService(List<Saml2Endpoint> manageNameIDService) {
		this.manageNameIDService = manageNameIDService;
		return _this();
	}

	public List<Saml2NameId> getNameIds() {
		return nameIds;
	}

	public T setNameIds(List<Saml2NameId> nameIds) {
		this.nameIds = nameIds;
		return _this();
	}

	public Saml2Endpoint getDiscovery() {
		return discovery;
	}

	public T setDiscovery(Saml2Endpoint discovery) {
		this.discovery = discovery;
		return _this();
	}

	public Saml2Endpoint getRequestInitiation() {
		return requestInitiation;
	}

	public T setRequestInitiation(Saml2Endpoint requestInitiation) {
		this.requestInitiation = requestInitiation;
		return _this();
	}
}
