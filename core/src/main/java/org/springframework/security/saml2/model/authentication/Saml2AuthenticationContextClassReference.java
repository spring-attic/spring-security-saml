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

package org.springframework.security.saml2.model.authentication;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.security.saml2.Saml2Exception;

import static org.springframework.security.saml2.model.authentication.Saml2AuthenticationContextClassReference.Saml2AuthenticationContextClassReferenceType.UNSPECIFIED;

public class Saml2AuthenticationContextClassReference {

	public enum Saml2AuthenticationContextClassReferenceType {
		/**
		 * Internet Protocol
		 */
		INTERNET_PROTOCOL("urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol"),

		/**
		 * Internet Protocol Password
		 */
		INTERNET_PROTOCOL_PASSWORD("urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"),

		/**
		 * Kerberos
		 */
		KERBEROS("urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"),

		/**
		 * Mobile One Factor Unregistered
		 */
		MOBILE_ONE_FACTOR_UNREG("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered"),

		/**
		 * Mobile Two Factor Unregistered
		 */
		MOBILE_TWO_FACTOR_UNREG("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered"),

		/**
		 * Mobile One Factor Contract
		 */
		MOBILE_ONE_FACTOR_CONTRACT("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract"),

		/**
		 * Mobile Two Factor Contract
		 */
		MOBILE_TWO_FACTOR_CONTRACT("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"),

		/**
		 * Password
		 */
		PASSWORD("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"),

		/**
		 * Password Protected Transport
		 */
		PASSWORD_PROTECTED_TRANSPORT("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"),

		/**
		 * Previous Session
		 */
		PREVIOUS_SESSION("urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"),

		/**
		 * X509 Public Key
		 */
		X509_PUBLIC_KEY("urn:oasis:names:tc:SAML:2.0:ac:classes:X509"),

		/**
		 * PGP
		 */
		PGP("urn:oasis:names:tc:SAML:2.0:ac:classes:PGP"),

		/**
		 * SPKI
		 */
		SPKI("urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI"),

		/**
		 * XML Digital Signature
		 */
		XML_DIGITAL_SIGNATURE("urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig"),

		/**
		 * Smart Card
		 */
		SMARTCARD("urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard"),

		/**
		 * Smart Card PKI
		 */
		SMARTCARD_PKI("urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"),

		/**
		 * Software PKI
		 */
		SOFTWARE_PKI("urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI"),

		/**
		 * Telephony
		 */
		TELEPHONY("urn:oasis:names:tc:SAML:2.0:ac:classes:Telephony"),

		/**
		 * Nomadic Telephony
		 */
		NOMADIC_TELEPHONY("urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony"),

		/**
		 * Personalized Telephony
		 */
		PERSONAL_TELEPHONY("urn:oasis:names:tc:SAML:2.0:ac:classes:PersonalTelephony"),

		/**
		 * Authenticated Telephony
		 */
		AUTHENTICATED_TELEPHONY("urn:oasis:names:tc:SAML:2.0:ac:classes:AuthenticatedTelephony"),

		/**
		 * Secure Remote Password
		 */
		SECURE_REMOTE_PASSWORD("urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword"),

		/**
		 * SSL/TLS Client
		 */
		TLS_CLIENT("urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"),

		/**
		 * Time Synchornized Token
		 */
		TIME_SYNC_TOKEN("urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"),

		/**
		 * unspecified
		 */
		UNSPECIFIED("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");


		private final String urn;

		Saml2AuthenticationContextClassReferenceType(String urn) {
			this.urn = urn;
		}

		@Override
		public String toString() {
			return urn;
		}
	}

	private static ConcurrentMap<Saml2AuthenticationContextClassReferenceType, Saml2AuthenticationContextClassReference>
		singletons = new ConcurrentHashMap<>();

	private final String value;
	private final Saml2AuthenticationContextClassReferenceType type;

	private Saml2AuthenticationContextClassReference(String value,
													Saml2AuthenticationContextClassReferenceType type) {
		this.value = value;
		this.type = type;
	}

	private Saml2AuthenticationContextClassReference(Saml2AuthenticationContextClassReferenceType type) {
		this(type.toString(), type);
	}

	public String getValue() {
		return value;
	}

	public URI getValueAsUri() {
		try {
			return new URI(getValue());
		} catch (URISyntaxException e) {
			throw new Saml2Exception(e);
		}
	}

	public Saml2AuthenticationContextClassReferenceType getType() {
		return type;
	}

	private static Saml2AuthenticationContextClassReferenceType getType(String ctxRef) {
		for (Saml2AuthenticationContextClassReferenceType ref : Saml2AuthenticationContextClassReferenceType.values()) {
			if (ref.urn.equalsIgnoreCase(ctxRef)) {
				return ref;
			}
		}
		return UNSPECIFIED;
	}

	public static Saml2AuthenticationContextClassReference fromUrn(String ctxRef) {
		final Saml2AuthenticationContextClassReferenceType type = getType(ctxRef);
		if (type.toString().equals(ctxRef)) {
			final Saml2AuthenticationContextClassReference result = singletons.get(type);
			if (result == null) {
				final Saml2AuthenticationContextClassReference instance =
					new Saml2AuthenticationContextClassReference(type);
				Saml2AuthenticationContextClassReference previous = singletons.putIfAbsent(type, instance);
				if (previous != null) {
					return previous;
				} else {
					return instance;
				}
			} else {
				return result;
			}
		} else {
			return new Saml2AuthenticationContextClassReference(ctxRef, UNSPECIFIED);
		}
	}

	public static Saml2AuthenticationContextClassReference fromUrn(Saml2AuthenticationContextClassReferenceType ctxRef) {
		return fromUrn(ctxRef.toString());
	}

	@Override
	public String toString() {
		return getValue();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof Saml2AuthenticationContextClassReference)) {
			return false;
		}

		Saml2AuthenticationContextClassReference that = (Saml2AuthenticationContextClassReference) o;

		if (!getValue().equals(that.getValue())) {
			return false;
		}
		return getType() == that.getType();

	}

	@Override
	public int hashCode() {
		int result = getValue().hashCode();
		result = 31 * result + getType().hashCode();
		return result;
	}
}
