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

package org.springframework.security.saml2.metadata;

import java.util.List;

public class SsoProvider extends Provider {

    private List<Endpoint> artifactResolutionService;
    private List<Endpoint> singleLogoutService;
    private List<Endpoint> manageNameIDService;
    private List<NameID> nameIDs;

    public List<Endpoint> getArtifactResolutionService() {
        return artifactResolutionService;
    }

    public List<Endpoint> getSingleLogoutService() {
        return singleLogoutService;
    }

    public List<Endpoint> getManageNameIDService() {
        return manageNameIDService;
    }

    public List<NameID> getNameIDs() {
        return nameIDs;
    }

    public SsoProvider setArtifactResolutionService(List<Endpoint> artifactResolutionService) {
        this.artifactResolutionService = artifactResolutionService;
        return this;
    }

    public SsoProvider setSingleLogoutService(List<Endpoint> singleLogoutService) {
        this.singleLogoutService = singleLogoutService;
        return this;
    }

    public SsoProvider setManageNameIDService(List<Endpoint> manageNameIDService) {
        this.manageNameIDService = manageNameIDService;
        return this;
    }

    public SsoProvider setNameIDs(List<NameID> nameIDs) {
        this.nameIDs = nameIDs;
        return this;
    }
}
