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
package saml.saml2.scratch;

public class InheritanceTest {

	public static void main(String[] args) {
		new D()
			.yetAnotherSet()
			.setSomething()
			.setSomethingElse()
			.anotherSet();
	}

	public static class A<T extends A<T>> {
		public T setSomething() {
			return _this();
		}

		@SuppressWarnings("unchecked")
		protected final T _this() {
			return (T) this;
		}
	}

	public static class B<T extends B<T>> extends A<T> {
		public T setSomethingElse() {
			return _this();
		}
	}

	public static class C<T extends C<T>> extends B<T> {
		public T anotherSet() {
			return _this();
		}
	}

	public static class D extends C<D> {

		public D yetAnotherSet() {
			return this;
		}

	}
}





