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

package org.springframework.security.saml;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.springframework.security.saml.saml2.Saml2Object;

public class ValidationResult {

	private final Saml2Object saml2Object;
	private List<ValidationError> errors = new LinkedList<>();

	public ValidationResult(Saml2Object saml2Object) {
		this.saml2Object = saml2Object;
	}

	public Saml2Object getSaml2Object() {
		return saml2Object;
	}

	public static class ValidationError {
		private String message;

		public ValidationError() {
		}

		public ValidationError(String message) {
			this.message = message;
		}


		public String getMessage() {
			return message;
		}

		public ValidationError setMessage(String message) {
			this.message = message;
			return this;
		}

		@Override
		public String toString() {
			return message;
		}
	}

	public ValidationResult addError(String error) {
		this.errors.add(new ValidationError(error));
		return this;
	}

	@Override
	public String toString() {
		final StringBuffer sb = new StringBuffer("Validation Errors: ");
		if (hasErrors()) {
			for (int i = 0; i < getErrors().size(); i++) {
				sb.append("\n");
				ValidationError error = getErrors().get(i);
				sb.append(i + 1);
				sb.append(". ");
				sb.append(error.getMessage());
			}
		}
		else {
			sb.append("None");
		}

		return sb.toString();
	}

	public ValidationResult addError(ValidationError error) {
		this.errors.add(error);
		return this;
	}

	public boolean hasErrors() {
		return !isSuccess();
	}

	public List<ValidationError> getErrors() {
		return Collections.unmodifiableList(errors);
	}

	public boolean isSuccess() {
		return errors.isEmpty();
	}

	public ValidationResult setErrors(List<ValidationError> errors) {
		this.errors.clear();
		this.errors.addAll(errors);
		return this;
	}


}
