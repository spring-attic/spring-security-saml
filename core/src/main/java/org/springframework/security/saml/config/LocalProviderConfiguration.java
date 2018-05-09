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

package org.springframework.security.saml.config;

import java.util.LinkedList;
import java.util.List;

import org.springframework.context.annotation.Configuration;

@Configuration
public class LocalProviderConfiguration {

    private List<ExternalProviderConfiguration> identityProviders = new LinkedList<>();
    private List<ExternalProviderConfiguration> serviceProviders = new LinkedList<>();

    public void setIdentityProviders(List<ExternalProviderConfiguration> idps) {
        this.identityProviders = idps;
    }

    public List<ExternalProviderConfiguration> getIdentityProviders() {
        return identityProviders;
    }

    public List<ExternalProviderConfiguration> getServiceProviders() {
        return serviceProviders;
    }

    public void setServiceProviders(List<ExternalProviderConfiguration> serviceProviders) {
        this.serviceProviders = serviceProviders;
    }
}
