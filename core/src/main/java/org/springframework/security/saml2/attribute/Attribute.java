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

package org.springframework.security.saml2.attribute;

import java.util.List;

public class Attribute {

    private String name;
    private List<Object> values;
    private String nameFormat;
    private String friendlyName;

    public String getName() {
        return name;
    }

    public Attribute setName(String name) {
        this.name = name;
        return this;
    }

    public List<Object> getValues() {
        return values;
    }

    public Attribute setValues(List<Object> values) {
        this.values = values;
        return this;
    }

    public String getNameFormat() {
        return nameFormat;
    }

    public Attribute setNameFormat(String nameFormat) {
        this.nameFormat = nameFormat;
        return this;
    }

    public String getFriendlyName() {
        return friendlyName;
    }

    public Attribute setFriendlyName(String friendlyName) {
        this.friendlyName = friendlyName;
        return this;
    }
}
