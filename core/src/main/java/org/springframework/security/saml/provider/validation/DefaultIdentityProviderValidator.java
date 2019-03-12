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
package org.springframework.security.saml.provider.validation;

import java.time.Clock;
import java.util.List;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.ValidationResult;
import org.springframework.security.saml.provider.HostedIdentityProvider;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.SignableSaml2Object;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.key.KeyData;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.util.Assert;

//TODO Move to Identity Provider module
public class DefaultIdentityProviderValidator extends AbstractSamlValidator<HostedIdentityProvider>
	implements IdentityProviderValidator {

	private SamlTransformer implementation;
	private int responseSkewTimeMillis = 1000 * 60 * 2; //two minutes
	private boolean allowUnsolicitedResponses = true;
	private int maxAuthenticationAgeMillis = 1000 * 60 * 60 * 24; //24 hours
	private Clock time = Clock.systemUTC();

	public DefaultIdentityProviderValidator(SamlTransformer implementation) {
		setSamlTransformer(implementation);
	}

	private void setSamlTransformer(SamlTransformer implementation) {
		this.implementation = implementation;
	}

	@Override
	public SamlTransformer getSamlTransformer() {
		return implementation;
	}

	public DefaultIdentityProviderValidator setTime(Clock time) {
		this.time = time;
		return this;
	}

	@Override
	public Signature validateSignature(SignableSaml2Object saml2Object, List<KeyData> verificationKeys) {
		return super.validateSignature(saml2Object, verificationKeys);
	}

	@Override
	public ValidationResult validate(Saml2Object saml2Object, HostedIdentityProvider provider) {
		Assert.notNull(saml2Object, "Object to be validated cannot be null");
		ValidationResult result;
		if (saml2Object instanceof ServiceProviderMetadata) {
			result = validate((ServiceProviderMetadata)saml2Object, provider);
		}
		else if (saml2Object instanceof AuthenticationRequest) {
			result = validate((AuthenticationRequest)saml2Object, provider);
		}
		else if (saml2Object instanceof LogoutRequest) {
			result = validate((LogoutRequest)saml2Object, provider);
		}
		else if (saml2Object instanceof LogoutResponse) {
			result = validate((LogoutResponse)saml2Object, provider);
		}
		else {
			throw new SamlException("No validation implemented for class:" + saml2Object.getClass().getName());
		}
		return result;

	}

	private ValidationResult validate(ServiceProviderMetadata metadata, HostedIdentityProvider provider) {
		return new ValidationResult(metadata);
	}

	private ValidationResult validate(AuthenticationRequest authnRequest, HostedIdentityProvider provider) {
		ValidationResult result = new ValidationResult(authnRequest);
		checkValidSignature(authnRequest, result);
		return result;
	}

	public int getResponseSkewTimeMillis() {
		return responseSkewTimeMillis;
	}

	public DefaultIdentityProviderValidator setResponseSkewTimeMillis(int responseSkewTimeMillis) {
		this.responseSkewTimeMillis = responseSkewTimeMillis;
		return this;
	}

	public boolean isAllowUnsolicitedResponses() {
		return allowUnsolicitedResponses;
	}

	public DefaultIdentityProviderValidator setAllowUnsolicitedResponses(boolean allowUnsolicitedResponses) {
		this.allowUnsolicitedResponses = allowUnsolicitedResponses;
		return this;
	}

	public int getMaxAuthenticationAgeMillis() {
		return maxAuthenticationAgeMillis;
	}

	public Clock time() {
		return time;
	}

	public void setMaxAuthenticationAgeMillis(int maxAuthenticationAgeMillis) {
		this.maxAuthenticationAgeMillis = maxAuthenticationAgeMillis;
	}


}
