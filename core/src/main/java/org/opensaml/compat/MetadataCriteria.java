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

package org.opensaml.compat;

import javax.xml.namespace.QName;

import net.shibboleth.utilities.java.support.resolver.Criterion;

/**
 * An implementation of {@link net.shibboleth.utilities.java.support.resolver.Criterion} which specifies criteria pertaining
 * to SAML 2 metadata.
 */
public final class MetadataCriteria implements Criterion {

    /** Metadata role indicated by the criteria. */
    private QName entityRole;

    /** Metadata protocol of the role indicated by the criteria. */
    private String entityProtocol;

    /**
     * Constructor.
     *
     * @param role the entity role
     * @param protocol the entity protocol
     */
    public MetadataCriteria(QName role, String protocol) {
       setRole(role);
       setProtocol(protocol);
    }

    /**
     * Get the entity protocol.
     *
     * @return the protocol.
     */
    public String getProtocol() {
        return entityProtocol;
    }

    /**
     * Set the entity protocol.
     *
     * @param protocol The protocol to set.
     */
    public void setProtocol(String protocol) {
        entityProtocol = DataTypeHelper.safeTrimOrNullString(protocol);
    }

    /**
     * Get the entity role.
     *
     * @return Returns the role.
     */
    public QName getRole() {
        return entityRole;
    }

    /**
     * Set the entity role.
     *
     * @param role the QName of entity role
     */
    public void setRole(QName role) {
        if (role == null) {
            throw new IllegalArgumentException("Role criteria may not be null");
        }
        entityRole = role;
    }





}
