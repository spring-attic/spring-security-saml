/* Copyright 2009 Vladimir Schafer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.saml;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.NameID;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.springframework.security.saml.parser.SAMLCollection;
import org.springframework.security.saml.parser.SAMLObject;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;

/**
 * Object is a storage for entities parsed from SAML2 response during its authentication. The object is stored
 * as credential object inside the Authentication returned after the authentication success.
 * <p>
 * The SAML entities (NameID, Assertion) are internally stored in SAMLObject to permit their serialization.
 *
 * @author Vladimir Schafer
 */
public class SAMLCredential implements Serializable {

    private SAMLObject<NameID> nameID;
    private SAMLObject<Assertion> authenticationAssertion;
    private String localEntityID;
    private String remoteEntityID;
    private String relayState;
    private Serializable additionalData;

    /**
     * Collection of attributes received from assertions.
     */
    private SAMLCollection<Attribute> attributes;

    /**
     * Created unmodifiable SAML credential object.
     *
     * @param nameID                  name ID of the authenticated entity
     * @param authenticationAssertion assertion used to validate the entity
     * @param remoteEntityID          identifier of IDP where the assertion came from
     * @param localEntityID           local entity ID
     */
    public SAMLCredential(NameID nameID, Assertion authenticationAssertion, String remoteEntityID, String localEntityID) {
        this(nameID, authenticationAssertion, remoteEntityID, Collections.<Attribute>emptyList(), localEntityID);
    }

    /**
     * Created unmodifiable SAML credential object.
     *
     * @param nameID                  name ID of the authenticated entity
     * @param authenticationAssertion assertion used to validate the entity
     * @param remoteEntityID          identifier of IDP where the assertion came from
     * @param attributes              attributes collected from received assertions
     * @param localEntityID           local entity ID
     */
    public SAMLCredential(NameID nameID, Assertion authenticationAssertion, String remoteEntityID, List<Attribute> attributes, String localEntityID) {
        this(nameID, authenticationAssertion, remoteEntityID, null, attributes, localEntityID);
    }

    /**
     * Created unmodifiable SAML credential object.
     *
     * @param nameID                  name ID of the authenticated entity, may be null
     * @param authenticationAssertion assertion used to validate the entity
     * @param remoteEntityID          identifier of IDP where the assertion came from
     * @param relayState              relay state received from IDP in case of unsolicited response
     * @param attributes              attributes collected from received assertions
     * @param localEntityID           local entity ID
     */
    public SAMLCredential(NameID nameID, Assertion authenticationAssertion, String remoteEntityID, String relayState, List<Attribute> attributes, String localEntityID) {
        this(nameID, authenticationAssertion, remoteEntityID, relayState, attributes, localEntityID, null);
    }

    /**
     * Created unmodifiable SAML credential object which contains additional customer specified data.
     *
     * @param nameID                  name ID of the authenticated entity, may be null
     * @param authenticationAssertion assertion used to validate the entity
     * @param remoteEntityID          identifier of IDP where the assertion came from
     * @param relayState              relay state received from IDP in case of unsolicited response
     * @param attributes              attributes collected from received assertions
     * @param localEntityID           local entity ID
     * @param additionalData          custom data created by profile customization
     */
    public SAMLCredential(NameID nameID, Assertion authenticationAssertion, String remoteEntityID, String relayState, List<Attribute> attributes, String localEntityID, Serializable additionalData) {
        this.nameID = new SAMLObject<NameID>(nameID);
        this.authenticationAssertion = new SAMLObject<Assertion>(authenticationAssertion);
        this.remoteEntityID = remoteEntityID;
        this.relayState = relayState;
        this.attributes = new SAMLCollection<Attribute>(attributes);
        this.localEntityID = localEntityID;
        this.additionalData = additionalData;
    }

    /**
     * NameID returned from IDP as part of the authentication process.
     *
     * @return name id or null if there was no nameID in the assertion used to create the SAMLCredential
     */
    public NameID getNameID() {
        return nameID.getObject();
    }

    /**
     * Assertion issued by IDP as part of the authentication process.
     *
     * @return assertion
     */
    public Assertion getAuthenticationAssertion() {
        return authenticationAssertion.getObject();
    }

    /**
     * Entity ID of the IDP which issued the assertion.
     *
     * @return IDP entity ID
     */
    public String getRemoteEntityID() {
        return remoteEntityID;
    }

    /**
     * Method searches for the first occurrence of the attribute with given name and returns it.
     * Name comparing is only done by "name" attribute, disregarding "friendly-name" and "name-format".
     * Attributes are searched in order as received in SAML message.
     *
     * Attribute names are case-insensitive.
     *
     * @param name name of attribute to find
     * @return the first occurrence of the attribute with the given name or null if not found
     */
    public Attribute getAttribute(String name) {
        for (Attribute attribute : getAttributes()) {
            if (name.equalsIgnoreCase(attribute.getName())) {
                return attribute;
            }
        }
        return null;
    }

    /**
     * Method searches for the first occurrence of the Attribute with given name. It returns text content of the first
     * AttributeValue element. In case there's multiple AttributeValues, the others are ignored. In case the Attribute
     * is not found or doesn't contain any values method returns null.
     *
     * The AttributeValue must be of type xs:String or xs:Any, other types are ignored and return null.
     *
     * Attribute names are case-insensitive.
     *
     * @param name name of attribute to find
     * @return the first occurrence of the attribute with the given name or null if not found
     */
    public String getAttributeAsString(String name) {
        Attribute attribute = getAttribute(name);
        if (attribute == null) {
            return null;
        }
        List<XMLObject> attributeValues = attribute.getAttributeValues();
        if (attributeValues == null || attributeValues.size() == 0) {
            return null;
        }
        XMLObject xmlValue = attributeValues.iterator().next();
        return getString(xmlValue);
    }

    /**
     * Method searches for the first occurrence of the Attribute with given name. It returns array with text contents of all
     * the AttributeValue elements. In case the Attribute is not found method returns null. In case Attribute doesn't contain
     * any values an empty array is returned. Array has always length equal to number of values in the attribute.
     *
     * The AttributeValues must be of type xs:String or xs:Any, other types are ignored and add null value to the array.
     *
     * Attribute names are case-insensitive.
     *
     * @param name name of attribute to find
     * @return the first occurrence of the attribute with the given name or null if not found
     */
    public String[] getAttributeAsStringArray(String name) {
        Attribute attribute = getAttribute(name);
        if (attribute == null) {
            return null;
        }
        List<XMLObject> attributeValues = attribute.getAttributeValues();
        if (attributeValues == null || attributeValues.size() == 0) {
            return new String[0];
        }
        String[] result = new String[attributeValues.size()];
        int i = 0;
        for (XMLObject attributeValue : attributeValues) {
            result[i++] = getString(attributeValue);
        }
        return result;
    }

    private String getString(XMLObject xmlValue) {
        if (xmlValue instanceof XSString) {
            return ((XSString) xmlValue).getValue();
        } else if (xmlValue instanceof XSAny) {
            return ((XSAny) xmlValue).getTextContent();
        } else {
            return null;
        }
    }

    /**
     * Unmodifiable list of all attributes loaded from the assertions received during SSO.
     * Attributes with the same name might be contained multiple times if received from different assertions.
     * Order of attributes is the same as declared in the received SAML message.
     *
     * @return unmodifiable list of users attributes
     */
    public List<Attribute> getAttributes() {
        return Collections.unmodifiableList(attributes.getObject());
    }

    /**
     * @return null if not set, relayState received from IDP otherwise
     */
    public String getRelayState() {
        return relayState;
    }

    /**
     * Entity ID of the local actor.
     *
     * @return entity ID
     */
    public String getLocalEntityID() {
        return localEntityID;
    }
    
    /**
     * Custom data created by profile customization
     *
     * @return custom data
     */
    public Serializable getAdditionalData() {
        return additionalData;
    }

}