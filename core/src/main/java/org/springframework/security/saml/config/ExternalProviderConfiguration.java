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

public class ExternalProviderConfiguration {
    private String name;
    private String url;
    private String metadata;
    private String linktext;
    private boolean trustcheck;

    public ExternalProviderConfiguration() {
    }

    public String getName() {
        return name;
    }

    public ExternalProviderConfiguration setName(String name) {
        this.name = name;
        return this;
    }

    public String getUrl() {
        return url;
    }

    public ExternalProviderConfiguration setUrl(String url) {
        this.url = url;
        return this;
    }

    public String getMetadata() {
        return metadata;
    }

    public ExternalProviderConfiguration setMetadata(String metadata) {
        this.metadata = metadata;
        return this;
    }

    public String getLinktext() {
        return linktext;
    }

    public ExternalProviderConfiguration setLinktext(String linktext) {
        this.linktext = linktext;
        return this;
    }

    public boolean isTrustcheck() {
        return trustcheck;
    }

    public ExternalProviderConfiguration setTrustcheck(boolean trustcheck) {
        this.trustcheck = trustcheck;
        return this;
    }
}
