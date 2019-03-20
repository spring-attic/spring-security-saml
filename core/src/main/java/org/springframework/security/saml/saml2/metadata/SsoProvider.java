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

package org.springframework.security.saml.saml2.metadata;

import java.util.LinkedList;
import java.util.List;

/**
 * Base class for SAML providers
 *
 * @param <T> return class for builder pattern
 */
public class SsoProvider<T extends SsoProvider<T>> extends Provider<T> {

	private List<Endpoint> artifactResolutionService = new LinkedList<>();
	private List<Endpoint> singleLogoutService = new LinkedList<>();
	private List<Endpoint> manageNameIDService = new LinkedList<>();
	private List<NameId> nameIds = new LinkedList<>();
	private Endpoint discovery;
	private Endpoint requestInitiation;

	public List<Endpoint> getArtifactResolutionService() {
		return artifactResolutionService;
	}

	public T setArtifactResolutionService(List<Endpoint> artifactResolutionService) {
		this.artifactResolutionService = artifactResolutionService;
		return _this();
	}

	public List<Endpoint> getSingleLogoutService() {
		return singleLogoutService;
	}

	public T setSingleLogoutService(List<Endpoint> singleLogoutService) {
		this.singleLogoutService = singleLogoutService;
		return _this();
	}

	public List<Endpoint> getManageNameIDService() {
		return manageNameIDService;
	}

	public T setManageNameIDService(List<Endpoint> manageNameIDService) {
		this.manageNameIDService = manageNameIDService;
		return _this();
	}

	public List<NameId> getNameIds() {
		return nameIds;
	}

	public T setNameIds(List<NameId> nameIds) {
		this.nameIds = nameIds;
		return _this();
	}

	public Endpoint getDiscovery() {
		return discovery;
	}

	public T setDiscovery(Endpoint discovery) {
		this.discovery = discovery;
		return _this();
	}

	public Endpoint getRequestInitiation() {
		return requestInitiation;
	}

	public T setRequestInitiation(Endpoint requestInitiation) {
		this.requestInitiation = requestInitiation;
		return _this();
	}
}
