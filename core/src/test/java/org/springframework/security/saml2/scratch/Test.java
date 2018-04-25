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

package org.springframework.security.saml2.scratch;

public class Test {
    public static void main(String... args) throws Exception {
        C c1 = new C()
            .<C>something()
            .<C>somethingElse()
            .<C>anotherSet();

        C c2 = new C()
            .<C>anotherSet()
            .<C>something()
            .<C>somethingElse();

        C c3 = new C()
            .<C>anotherSet()
            .<C>something()
            .<C>somethingElse();
    }

    public static class A {

        public <T> T something() {
            return (T)this;
        }
    }

    public static class B extends A  {

        public <T> T somethingElse() {
            return (T) this;
        }
    }

    public static class C extends B {

        public <T> T anotherSet() {
            return (T) this;
        }
    }
}

