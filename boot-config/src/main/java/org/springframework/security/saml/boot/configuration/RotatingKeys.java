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

package org.springframework.security.saml.boot.configuration;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.saml.saml2.key.KeyType;
import org.springframework.security.saml.saml2.key.KeyData;

import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

public class RotatingKeys {
	@NestedConfigurationProperty
	private SamlKey active = null;
	@NestedConfigurationProperty
	private List<SamlKey> standBy = new LinkedList<>();

	public List<KeyData> toList() {
		LinkedList<KeyData> result = new LinkedList<>();
		if (getActive()!=null) {
			result.add(getActive().toKeyData());
			result.add(getActive().toKeyData(getActive().getName()+"-encrypt", KeyType.ENCRYPTION));
		}
		result.addAll(
			ofNullable(getStandBy()).orElse(Collections.emptyList())
				.stream().map(k -> k.toKeyData())
				.collect(Collectors.toList())
		);
		return result;
	}

	public SamlKey getActive() {
		return active;
	}

	public void setActive(SamlKey active) {
		this.active = active;
		if (!hasText(active.getName())) {
			active.setName("active-key");
		}
	}

	public List<SamlKey> getStandBy() {
		return standBy;
	}

	public void setStandBy(List<SamlKey> standBy) {
		this.standBy = standBy;
	}
}
