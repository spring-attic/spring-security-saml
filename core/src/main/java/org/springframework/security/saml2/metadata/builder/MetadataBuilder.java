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

package org.springframework.security.saml2.metadata.builder;

import java.net.URI;
import java.net.URISyntaxException;

import org.springframework.security.saml2.metadata.InvalidMetadataException;

import static org.springframework.util.StringUtils.isEmpty;

public class MetadataBuilder {


    private String baseUrl;

    protected MetadataBuilder(String baseUrl) {
        if (isEmpty(baseUrl)) {
            throw new InvalidMetadataException("Invalid base URL for metadata:'"+baseUrl+"'");
        }
        try {
            new URI(baseUrl);
        } catch (URISyntaxException e) {
            throw new InvalidMetadataException("Invalid base URL for metadata:'"+baseUrl+"'", e);
        }
        this.baseUrl = baseUrl;
    }




}
