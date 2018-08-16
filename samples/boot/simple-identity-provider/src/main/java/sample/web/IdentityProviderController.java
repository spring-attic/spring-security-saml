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
*/package sample.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import sample.config.AppConfig;

@Controller
public class IdentityProviderController {
	private static final Log logger =LogFactory.getLog(IdentityProviderController.class);
	private SamlServerConfiguration configuration;
	private SamlProviderProvisioning<IdentityProviderService> provisioning;


	@Autowired
	public void setAppConfig(AppConfig config) {
		this.configuration = config;
	}

	@Autowired
	public void setSamlProviderProvisioning(SamlProviderProvisioning<IdentityProviderService> provisioning) {
		this.provisioning = provisioning;
	}

	@RequestMapping(value = {"/"})
	public String selectProvider() {
		return "redirect:/saml/idp/select";
	}


}
