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
/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.validation;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class ValidationResult {

	private List<ValidationError> errors = new LinkedList<>();

	public boolean isSuccess() {
		return errors.isEmpty();
	}

	public List<ValidationError> getErrors() {
		return Collections.unmodifiableList(errors);
	}

	public ValidationResult setErrors(List<ValidationError> errors) {
		this.errors.clear();
		this.errors.addAll(errors);
		return this;
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

	public ValidationResult addError(ValidationError error) {
		this.errors.add(error);
		return this;
	}
}
