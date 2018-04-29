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

package org.springframework.security.saml2.authentication;

import java.util.List;

public abstract class SubjectPrincipal<T extends SubjectPrincipal> {

    @SuppressWarnings("checked")
    protected T _this() {
        return (T)this;
    }

    private List<SubjectConfirmationData> confirmationData;

    public List<SubjectConfirmationData> getConfirmationData() {
        return confirmationData;
    }

    public T setConfirmationData(List<SubjectConfirmationData> confirmationData) {
        this.confirmationData = confirmationData;
        return _this();
    }
}
