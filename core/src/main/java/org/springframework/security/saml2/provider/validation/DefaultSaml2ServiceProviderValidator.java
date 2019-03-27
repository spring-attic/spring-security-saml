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
package org.springframework.security.saml2.provider.validation;

import java.time.Clock;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.Saml2Transformer;
import org.springframework.security.saml2.Saml2ValidationResult;
import org.springframework.security.saml2.Saml2ValidationResult.ValidationError;
import org.springframework.security.saml2.provider.HostedSaml2ServiceProvider;
import org.springframework.security.saml2.model.Saml2Object;
import org.springframework.security.saml2.model.Saml2SignableObject;
import org.springframework.security.saml2.model.authentication.Saml2Assertion;
import org.springframework.security.saml2.model.authentication.Saml2AssertionCondition;
import org.springframework.security.saml2.model.authentication.Saml2AudienceRestriction;
import org.springframework.security.saml2.model.authentication.Saml2AuthenticationStatement;
import org.springframework.security.saml2.model.authentication.Saml2Conditions;
import org.springframework.security.saml2.model.authentication.Saml2LogoutSaml2Request;
import org.springframework.security.saml2.model.authentication.Saml2LogoutResponseSaml2;
import org.springframework.security.saml2.model.authentication.Saml2ResponseSaml2;
import org.springframework.security.saml2.model.authentication.Saml2StatusCode;
import org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmation;
import org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmationData;
import org.springframework.security.saml2.model.key.Saml2KeyData;
import org.springframework.security.saml2.model.metadata.Saml2IdentityProviderMetadata;
import org.springframework.security.saml2.model.metadata.Saml2ServiceProviderMetadata;
import org.springframework.security.saml2.model.signature.Saml2Signature;
import org.springframework.security.saml2.model.signature.Saml2SignatureException;
import org.springframework.util.Assert;

import org.joda.time.DateTime;

import static java.lang.String.format;
import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.springframework.security.saml2.model.authentication.Saml2SubjectConfirmationMethod.BEARER;
import static org.springframework.security.saml2.util.Saml2DateUtils.toZuluTime;
import static org.springframework.util.StringUtils.hasText;

public class DefaultSaml2ServiceProviderValidator extends AbstractSaml2Validator<HostedSaml2ServiceProvider>
	implements Saml2ServiceProviderValidator {

	private Saml2Transformer implementation;
	private int responseSkewTimeMillis = 1000 * 60 * 2; //two minutes
	private boolean allowUnsolicitedResponses = true;
	private int maxAuthenticationAgeMillis = 1000 * 60 * 60 * 24; //24 hours
	private Clock time = Clock.systemUTC();

	public DefaultSaml2ServiceProviderValidator(Saml2Transformer implementation) {
		setTransformer(implementation);
	}

	private void setTransformer(Saml2Transformer implementation) {
		this.implementation = implementation;
	}

	@Override
	public Saml2Transformer getSamlTransformer() {
		return implementation;
	}

	public DefaultSaml2ServiceProviderValidator setTime(Clock time) {
		this.time = time;
		return this;
	}

	@Override
	public Saml2Signature validateSignature(Saml2SignableObject saml2Object, List<Saml2KeyData> verificationKeys)
		throws Saml2SignatureException {
		return super.validateSignature(saml2Object, verificationKeys);
	}

	@Override
	public Saml2ValidationResult validate(Saml2Object saml2Object, HostedSaml2ServiceProvider provider) {
		Assert.notNull(saml2Object, "Object to be validated cannot be null");
		Saml2ValidationResult result;
		if (saml2Object instanceof Saml2IdentityProviderMetadata) {
			result = validate((Saml2IdentityProviderMetadata) saml2Object, provider);
		}
		else if (saml2Object instanceof Saml2LogoutSaml2Request) {
			result = validate((Saml2LogoutSaml2Request) saml2Object, provider);
		}
		else if (saml2Object instanceof Saml2LogoutResponseSaml2) {
			result = validate((Saml2LogoutResponseSaml2) saml2Object, provider);
		}
		else if (saml2Object instanceof Saml2ResponseSaml2) {
			Saml2ResponseSaml2 r = (Saml2ResponseSaml2) saml2Object;
			Saml2ServiceProviderMetadata requester = provider.getMetadata();
			Saml2IdentityProviderMetadata responder = provider.getRemoteProvider(r.getOriginEntityId());
			result = validate(r, null, requester, responder);
		}
		else if (saml2Object instanceof Saml2Assertion) {
			Saml2Assertion a = (Saml2Assertion) saml2Object;
			Saml2ServiceProviderMetadata requester = provider.getMetadata();
			Saml2IdentityProviderMetadata responder = provider.getRemoteProvider(a.getOriginEntityId());
			result = validate(a, null, requester, responder, requester.getServiceProvider().isWantAssertionsSigned());
		}
		else {
			throw new Saml2Exception("No validation implemented for class:" + saml2Object.getClass().getName());
		}
		return result;
	}

	private Saml2ValidationResult validate(Saml2IdentityProviderMetadata metadata, HostedSaml2ServiceProvider provider) {
		return new Saml2ValidationResult(metadata);
	}

	private Saml2ValidationResult validate(Saml2Assertion assertion,
										   List<String> mustMatchInResponseTo,
										   Saml2ServiceProviderMetadata requester,
										   Saml2IdentityProviderMetadata responder,
										   boolean requireAssertionsSigned) {
		//verify assertion
		//issuer
		//signature
		if (requireAssertionsSigned && !assertion.isEncrypted()) {
			if (assertion.getSignature() == null || !assertion.getSignature().isValidated()) {
				return
					new Saml2ValidationResult(assertion).addError(
						new ValidationError("Assertion is not signed or signature was not validated")
					);
			}
		}

		if (responder == null) {
			return new Saml2ValidationResult(assertion)
				.addError("Remote provider for assertion was not found");
		}

		List<Saml2SubjectConfirmation> validConfirmations = new LinkedList<>();
		Saml2ValidationResult assertionValidation = new Saml2ValidationResult(assertion);
		for (Saml2SubjectConfirmation conf : assertion.getSubject().getConfirmations()) {

			assertionValidation.setErrors(emptyList());
			//verify assertion subject for BEARER
			if (!BEARER.equals(conf.getMethod())) {
				assertionValidation.addError("Invalid confirmation method:" + conf.getMethod());
				continue;
			}

			//for each subject confirmation data
			//1. data must not be null
			Saml2SubjectConfirmationData data = conf.getConfirmationData();
			if (data == null) {
				assertionValidation.addError(new ValidationError("Empty subject confirmation data"));
				continue;
			}


			//2. NotBefore must be null (saml-profiles-2.0-os 558)
			// Not before forbidden by saml-profiles-2.0-os 558
			if (data.getNotBefore() != null) {
				assertionValidation.addError(
					new ValidationError("Subject confirmation data should not have NotBefore date")
				);
				continue;
			}
			//3. NotOnOfAfter must not be null and within skew
			if (data.getNotOnOrAfter() == null) {
				assertionValidation.addError(
					new ValidationError("Subject confirmation data is missing NotOnOfAfter date")
				);
				continue;
			}

			if (data.getNotOnOrAfter().plusMillis(getResponseSkewTimeMillis()).isBeforeNow()) {
				assertionValidation.addError(
					new ValidationError(format("Invalid NotOnOrAfter date: '%s'", data.getNotOnOrAfter()))
				);
			}
			//4. InResponseTo if it exists
			if (hasText(data.getInResponseTo())) {
				if (mustMatchInResponseTo != null) {
					if (!mustMatchInResponseTo.contains(data.getInResponseTo())) {
						assertionValidation.addError(
							new ValidationError(
								format("No match for InResponseTo: '%s' found", data.getInResponseTo())
							)
						);
						continue;
					}
				}
				else if (!isAllowUnsolicitedResponses()) {
					assertionValidation.addError(
						new ValidationError(
							"InResponseTo missing and system not configured to allow unsolicited messages")
					);
					continue;
				}
			}
			//5. Recipient must match ACS URL
			if (!hasText(data.getRecipient())) {
				assertionValidation.addError(new ValidationError("Assertion Recipient field missing"));
				continue;
			}
			else if (!compareURIs(
				requester.getServiceProvider().getAssertionConsumerService(),
				data.getRecipient()
			)) {
				assertionValidation.addError(
					new ValidationError("Invalid assertion Recipient field: " + data.getRecipient())
				);
				continue;
			}

			if (!assertionValidation.hasErrors()) {
				validConfirmations.add(conf);
			}

		}
		if (assertionValidation.hasErrors()) {
			return assertionValidation;
		}
		assertion.getSubject().setConfirmations(validConfirmations);
		//6. DECRYPT NAMEID if it is encrypted
		//6b. Use regular NameID
		if ((assertion.getSubject().getPrincipal()) == null) {
			//we have a valid assertion, that's the one we will be using
			return new Saml2ValidationResult(assertion).addError("Assertion principal is missing");
		}
		return new Saml2ValidationResult(assertion);
	}

	private Saml2ValidationResult validate(Saml2ResponseSaml2 response,
										   List<String> mustMatchInResponseTo,
										   Saml2ServiceProviderMetadata requester,
										   Saml2IdentityProviderMetadata responder) {
		String entityId = requester.getEntityId();

		if (response == null) {
			return new Saml2ValidationResult(response).addError(new ValidationError("Response is null"));
		}

		if (response.getStatus() == null || response.getStatus().getCode() == null) {
			return new Saml2ValidationResult(response).addError(new ValidationError("Response status or code is null"));
		}

		Saml2StatusCode statusCode = response.getStatus().getCode();
		if (statusCode != Saml2StatusCode.SUCCESS) {
			return new Saml2ValidationResult(response).addError(
				new ValidationError("An error response was returned: " + statusCode.toString())
			);
		}

		if (responder == null) {
			return new Saml2ValidationResult(response)
				.addError("Remote provider for response was not found");
		}

		if (response.getSignature() != null && !response.getSignature().isValidated()) {
			return new Saml2ValidationResult(response).addError(new ValidationError("No validated signature present"));
		}

		//verify issue time
		DateTime issueInstant = response.getIssueInstant();
		if (!isDateTimeSkewValid(getResponseSkewTimeMillis(), 0, issueInstant)) {
			return new Saml2ValidationResult(response).addError(
				new ValidationError("Issue time is either too old or in the future:" + issueInstant.toString())
			);
		}

		//validate InResponseTo
		String replyTo = response.getInResponseTo();
		if (!isAllowUnsolicitedResponses() && !hasText(replyTo)) {
			return new Saml2ValidationResult(response).addError(
				new ValidationError("InResponseTo is missing and unsolicited responses are disabled")
			);
		}

		if (hasText(replyTo)) {
			if (!isAllowUnsolicitedResponses() && (mustMatchInResponseTo == null || !mustMatchInResponseTo
				.contains(replyTo))) {
				return new Saml2ValidationResult(response).addError(
					new ValidationError("Invalid InResponseTo ID, not found in supplied list")
				);
			}
		}

		//validate destination
		if (hasText(response.getDestination()) && !compareURIs(requester.getServiceProvider()
			.getAssertionConsumerService(), response.getDestination())) {
			return new Saml2ValidationResult(response).addError(
				new ValidationError("Destination mismatch: " + response.getDestination())
			);
		}

		//validate issuer
		//name id if not null should be "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
		//value should be the entity ID of the responder
		Saml2ValidationResult result = verifyIssuer(response.getIssuer(), responder);
		if (result != null) {
			return result;
		}

		boolean requireAssertionSigned = requester.getServiceProvider().isWantAssertionsSigned();
		if (response.getSignature() != null) {
			requireAssertionSigned = requireAssertionSigned && (!response.getSignature().isValidated());
		}

		Saml2Assertion validAssertion = null;
		Saml2ValidationResult assertionValidation = new Saml2ValidationResult(response);
		//DECRYPT ENCRYPTED ASSERTIONS
		for (Saml2Assertion assertion : response.getAssertions()) {

			Saml2ValidationResult assertionResult = validate(
				assertion,
				mustMatchInResponseTo,
				requester,
				responder,
				requireAssertionSigned
			);
			if (!assertionResult.hasErrors()) {
				validAssertion = assertion;
				break;
			}
		}
		if (validAssertion == null) {
			assertionValidation.addError(new ValidationError("No valid assertion with principal found."));
			return assertionValidation;
		}

		for (Saml2AuthenticationStatement statement : ofNullable(validAssertion.getAuthenticationStatements())
			.orElse(emptyList())) {
			//VERIFY authentication statements
			if (!isDateTimeSkewValid(
				getResponseSkewTimeMillis(),
				getMaxAuthenticationAgeMillis(),
				statement.getAuthInstant()
			)) {
				return new Saml2ValidationResult(response)
					.addError(
						format(
							"Authentication statement is too old to be used with value: '%s' current time: '%s'",
							toZuluTime(statement.getAuthInstant()),
							toZuluTime(new DateTime())
						)
					);
			}

			if (statement.getSessionNotOnOrAfter() != null && statement.getSessionNotOnOrAfter().isBeforeNow
				()) {
				return new Saml2ValidationResult(response)
					.addError(
						format(
							"Authentication session expired on: '%s', current time: '%s'",
							toZuluTime(statement.getSessionNotOnOrAfter()),
							toZuluTime(new DateTime())
						)
					);
			}

			//possibly check the
			//statement.getAuthenticationContext().getClassReference()
		}

		Saml2Conditions conditions = validAssertion.getConditions();
		if (conditions != null) {
			//VERIFY conditions
			if (conditions.getNotBefore() != null && conditions.getNotBefore().minusMillis
				(getResponseSkewTimeMillis()).isAfterNow()) {
				return new Saml2ValidationResult(response)
					.addError("Conditions expired (not before): " + conditions.getNotBefore());
			}

			if (conditions.getNotOnOrAfter() != null && conditions.getNotOnOrAfter().plusMillis
				(getResponseSkewTimeMillis()).isBeforeNow()) {
				return new Saml2ValidationResult(response)
					.addError("Conditions expired (not on or after): " + conditions.getNotOnOrAfter());
			}

			for (Saml2AssertionCondition c : conditions.getCriteria()) {
				if (c instanceof Saml2AudienceRestriction) {
					Saml2AudienceRestriction ac = (Saml2AudienceRestriction) c;
					ac.evaluate(entityId, time());
					if (!ac.isValid()) {
						return new Saml2ValidationResult(response)
							.addError(
								format(
									"Audience restriction evaluation failed for assertion condition. Expected '%s' Was '%s'",
									entityId,
									ac.getAudiences()
								)
							);
					}
				}
			}
		}

		//the only assertion that we validated - may not be the first one
		response.setAssertions(Arrays.asList(validAssertion));
		return new Saml2ValidationResult(response);
	}

	public int getResponseSkewTimeMillis() {
		return responseSkewTimeMillis;
	}

	public DefaultSaml2ServiceProviderValidator setResponseSkewTimeMillis(int responseSkewTimeMillis) {
		this.responseSkewTimeMillis = responseSkewTimeMillis;
		return this;
	}

	public boolean isAllowUnsolicitedResponses() {
		return allowUnsolicitedResponses;
	}

	public DefaultSaml2ServiceProviderValidator setAllowUnsolicitedResponses(boolean allowUnsolicitedResponses) {
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
