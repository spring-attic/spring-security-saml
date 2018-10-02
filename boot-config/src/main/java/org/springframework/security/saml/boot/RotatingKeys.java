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

package org.springframework.security.saml.boot;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.saml.key.SimpleKey;

import static org.springframework.util.StringUtils.hasText;

public class RotatingKeys {
	@NestedConfigurationProperty
	private SamlKey active = null;
	@NestedConfigurationProperty
	private List<SamlKey> standBy = new LinkedList<>();

	public List<SimpleKey> toList() {
		LinkedList<SimpleKey> result = new LinkedList<>();
		result.add(getActive().toSimpleKey());
		result.addAll(
			getStandBy().stream().map(
				k -> k.toSimpleKey()
			).collect(Collectors.toList())
		);
		return result;
	}

	public SamlKey getActive() {
		return active;
	}

	public void setActive(SamlKey active) {

		if (hasText(active.getName())) {
			this.active = active;
		}
		else {
			this.active = new SamlKey(
				"active-signing-key",
				active.getPrivateKey(),
				active.getCertificate(),
				active.getPassphrase(),
				active.getType()
			);
		}
	}

	public List<SamlKey> getStandBy() {
		return standBy;
	}

	public void setStandBy(List<SamlKey> standBy) {
		this.standBy = standBy;
	}
}
