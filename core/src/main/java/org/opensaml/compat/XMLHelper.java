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

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.Duration;
import javax.xml.namespace.QName;
import java.io.OutputStream;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.StringTokenizer;

import net.shibboleth.utilities.java.support.collection.LazyMap;
import net.shibboleth.utilities.java.support.xml.XMLConstants;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLRuntimeException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.AttributeMap;
import org.w3c.dom.Attr;
import org.w3c.dom.DOMConfiguration;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.Text;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.w3c.dom.ls.LSSerializerFilter;

/**
 * A helper class for working with W3C DOM objects.
 */
public final class XMLHelper {

    /**
     * A string which contains the valid delimiters for the XML Schema 'list' type. These are: space, newline, carriage
     * return, and tab.
     */
    public static final String LIST_DELIMITERS = " \n\r\t";

    /** DOM configuration parameters used by LSSerializer in pretty print format output. */
    private static Map<String, Object> prettyPrintParams;

    /** JAXP DatatypeFactory. */
    private static DatatypeFactory dataTypeFactory;

    /** Constructor. */
    private XMLHelper() {

    }

    /**
     * Gets a static instance of a JAXP DatatypeFactory.
     *
     * @return the factory or null if the factory could not be created
     */
    public static DatatypeFactory getDataTypeFactory() {
        if (dataTypeFactory == null) {
            try {
                dataTypeFactory = DatatypeFactory.newInstance();
            } catch (DatatypeConfigurationException e) {
                // do nothing
            }
        }

        return dataTypeFactory;
    }

    /**
     * Checks if the given element has an xsi:type defined for it.
     *
     * @param e the DOM element
     *
     * @return true if there is a type, false if not
     */
    public static boolean hasXSIType(Element e) {
        if (e != null) {
            if (e.getAttributeNodeNS(XMLConstants.XSI_NS, "type") != null) {
                return true;
            }
        }

        return false;
    }

    /**
     * Gets the XSI type for a given element if it has one.
     *
     * @param e the element
     *
     * @return the type or null
     */
    public static QName getXSIType(Element e) {
        if (hasXSIType(e)) {
            Attr attribute = e.getAttributeNodeNS(XMLConstants.XSI_NS, "type");
            String attributeValue = attribute.getTextContent().trim();
            StringTokenizer tokenizer = new StringTokenizer(attributeValue, ":");
            String prefix = null;
            String localPart;
            if (tokenizer.countTokens() > 1) {
                prefix = tokenizer.nextToken();
                localPart = tokenizer.nextToken();
            } else {
                localPart = tokenizer.nextToken();
            }

            return constructQName(e.lookupNamespaceURI(prefix), localPart, prefix);
        }

        return null;
    }

    /**
     * Gets the ID attribute of a DOM element.
     *
     * @param domElement the DOM element
     *
     * @return the ID attribute or null if there isn't one
     */
    public static Attr getIdAttribute(Element domElement) {
        if (!domElement.hasAttributes()) {
            return null;
        }

        NamedNodeMap attributes = domElement.getAttributes();
        Attr attribute;
        for (int i = 0; i < attributes.getLength(); i++) {
            attribute = (Attr) attributes.item(i);
            if (attribute.isId()) {
                return attribute;
            }
        }

        return null;
    }

    /**
     * Gets the QName for the given DOM node.
     *
     * @param domNode the DOM node
     *
     * @return the QName for the element or null if the element was null
     */
    public static QName getNodeQName(Node domNode) {
        if (domNode != null) {
            return constructQName(domNode.getNamespaceURI(), domNode.getLocalName(), domNode.getPrefix());
        }

        return null;
    }

    /**
     * Gets the lcoale currently active for the element. This is done by looking for an xml:lang attribute and parsing
     * its content. If no xml:lang attribute is present the default locale is returned. This method only uses the
     * language primary tag, as defined by RFC3066.
     *
     * @param element element to retrieve local information for
     *
     * @return the active local of the element
     */
    public static Locale getLanguage(Element element) {
        String lang = DataTypeHelper.safeTrimOrNullString(element.getAttributeNS(XMLConstants.XML_NS, "lang"));
        if (lang != null) {
            if (lang.contains("-")) {
                lang = lang.substring(0, lang.indexOf("-"));
            }
            return new Locale(lang.toUpperCase());
        } else {
            return Locale.getDefault();
        }
    }

    /**
     * Constructs an attribute owned by the given document with the given name.
     *
     * @param owningDocument the owning document
     * @param attributeName the name of that attribute
     *
     * @return the constructed attribute
     */
    public static Attr constructAttribute(Document owningDocument, QName attributeName) {
        return constructAttribute(owningDocument, attributeName.getNamespaceURI(), attributeName.getLocalPart(),
                                  attributeName.getPrefix());
    }

    /**
     * Constructs an attribute owned by the given document with the given name.
     *
     * @param document the owning document
     * @param namespaceURI the URI for the namespace the attribute is in
     * @param localName the local name
     * @param prefix the prefix of the namespace that attribute is in
     *
     * @return the constructed attribute
     */
    public static Attr constructAttribute(Document document, String namespaceURI, String localName, String prefix) {
        String trimmedLocalName = DataTypeHelper.safeTrimOrNullString(localName);

        if (trimmedLocalName == null) {
            throw new IllegalArgumentException("Local name may not be null or empty");
        }

        String qualifiedName;
        String trimmedPrefix = DataTypeHelper.safeTrimOrNullString(prefix);
        if (trimmedPrefix != null) {
            qualifiedName = trimmedPrefix + ":" + DataTypeHelper.safeTrimOrNullString(trimmedLocalName);
        } else {
            qualifiedName = DataTypeHelper.safeTrimOrNullString(trimmedLocalName);
        }

        if (DataTypeHelper.isEmpty(namespaceURI)) {
            return document.createAttributeNS(null, qualifiedName);
        } else {
            return document.createAttributeNS(namespaceURI, qualifiedName);
        }
    }

    /**
     * Constructs a QName from an attributes value.
     *
     * @param attribute the attribute with a QName value
     *
     * @return a QName from an attributes value, or null if the given attribute is null
     */
    public static QName getAttributeValueAsQName(Attr attribute) {
        if (attribute == null || DataTypeHelper.isEmpty(attribute.getValue())) {
            return null;
        }

        String attributeValue = attribute.getTextContent();
        String[] valueComponents = attributeValue.split(":");
        if (valueComponents.length == 1) {
            return constructQName(attribute.lookupNamespaceURI(null), valueComponents[0], null);
        } else {
            return constructQName(attribute.lookupNamespaceURI(valueComponents[0]), valueComponents[1],
                                  valueComponents[0]);
        }
    }

    /**
     * Parses the attribute's value. If the value is 0 or "false" then false is returned, if the value is 1 or "true"
     * then true is returned, if the value is anything else then null returned.
     *
     * @param attribute attribute whose value will be converted to a boolean
     *
     * @return boolean value of the attribute or null
     */
    public static Boolean getAttributeValueAsBoolean(Attr attribute) {
        if (attribute == null) {
            return null;
        }

        String valueStr = attribute.getValue();
        if (valueStr.equals("0") || valueStr.equals("false")) {
            return Boolean.FALSE;
        } else if (valueStr.equals("1") || valueStr.equals("true")) {
            return Boolean.TRUE;
        } else {
            return null;
        }
    }

    /**
     * Gets the value of a list-type attribute as a list.
     *
     * @param attribute attribute whose value will be turned into a list
     *
     * @return list of values, never null
     */
    public static List<String> getAttributeValueAsList(Attr attribute) {
        if (attribute == null) {
            return Collections.emptyList();
        }
        return DataTypeHelper.stringToList(attribute.getValue(), LIST_DELIMITERS);
    }

    /**
     * Marshall an attribute name and value to a DOM Element. This is particularly useful for attributes whose names
     * appear in namespace-qualified form.
     *
     * @param attributeName the attribute name in QName form
     * @param attributeValue the attribute value
     * @param domElement the target element to which to marshall
     * @param isIDAttribute flag indicating whether the attribute being marshalled should be handled as an ID-typed
     *            attribute
     */
    public static void marshallAttribute(QName attributeName, String attributeValue, Element domElement,
                                         boolean isIDAttribute) {
        Document document = domElement.getOwnerDocument();
        Attr attribute = XMLHelper.constructAttribute(document, attributeName);
        attribute.setValue(attributeValue);
        domElement.setAttributeNodeNS(attribute);
        if (isIDAttribute) {
            domElement.setIdAttributeNode(attribute, true);
        }
    }

    /**
     * Marshall an attribute name and value to a DOM Element. This is particularly useful for attributes whose names
     * appear in namespace-qualified form.
     *
     * @param attributeName the attribute name in QName form
     * @param attributeValues the attribute values
     * @param domElement the target element to which to marshall
     * @param isIDAttribute flag indicating whether the attribute being marshalled should be handled as an ID-typed
     *            attribute
     */
    public static void marshallAttribute(QName attributeName, List<String> attributeValues, Element domElement,
                                         boolean isIDAttribute) {
        marshallAttribute(attributeName, DataTypeHelper.listToStringValue(attributeValues, " "), domElement,
                          isIDAttribute);
    }

    /**
     * Marshall the attributes represented by the indicated AttributeMap into the indicated DOM Element.
     *
     * @param attributeMap the AttributeMap
     * @param domElement the target Element
     */
    public static void marshallAttributeMap(AttributeMap attributeMap, Element domElement) {
        Document document = domElement.getOwnerDocument();
        Attr attribute = null;
        for (Entry<QName, String> entry : attributeMap.entrySet()) {
            attribute = XMLHelper.constructAttribute(document, entry.getKey());
            attribute.setValue(entry.getValue());
            domElement.setAttributeNodeNS(attribute);
            if (XMLObjectProviderRegistrySupport.isIDAttribute(entry.getKey()) || attributeMap.isIDAttribute(entry.getKey())) {
                domElement.setIdAttributeNode(attribute, true);
            }
        }
    }

    /**
     * Unmarshall a DOM Attr to an AttributeMap.
     *
     * @param attributeMap the target AttributeMap
     * @param attribute the target DOM Attr
     */
    public static void unmarshallToAttributeMap(AttributeMap attributeMap, Attr attribute) {
        QName attribQName = XMLHelper.constructQName(attribute.getNamespaceURI(), attribute.getLocalName(), attribute
            .getPrefix());
        attributeMap.put(attribQName, attribute.getValue());
        if (attribute.isId() || XMLObjectProviderRegistrySupport.isIDAttribute(attribQName)) {
            attributeMap.registerID(attribQName);
        }
    }

    /**
     * Constructs a QName from an element's adjacent Text child nodes.
     *
     * @param element the element with a QName value
     *
     * @return a QName from an element's value, or null if the given element is empty
     */
    public static QName getElementContentAsQName(Element element) {
        if (element == null) {
            return null;
        }

        String elementContent = null;
        Node child = element.getFirstChild();
        while (child != null) {
            if (child.getNodeType() == Node.TEXT_NODE) {
                elementContent = DataTypeHelper.safeTrimOrNullString(((Text) child).getWholeText());
                break;
            }
            child = child.getNextSibling();
        }

        if (elementContent == null) {
            return null;
        }

        String[] valueComponents = elementContent.split(":");
        if (valueComponents.length == 1) {
            return constructQName(element.lookupNamespaceURI(null), valueComponents[0], null);
        } else {
            return constructQName(element.lookupNamespaceURI(valueComponents[0]), valueComponents[1],
                                  valueComponents[0]);
        }
    }

    /**
     * Gets the value of a list-type element as a list.
     *
     * @param element element whose value will be turned into a list
     *
     * @return list of values, never null
     */
    public static List<String> getElementContentAsList(Element element) {
        if (element == null) {
            return Collections.emptyList();
        }
        return DataTypeHelper.stringToList(element.getTextContent(), LIST_DELIMITERS);
    }

    /**
     * Constructs a QName.
     *
     * @param namespaceURI the namespace of the QName
     * @param localName the local name of the QName
     * @param prefix the prefix of the QName, may be null
     *
     * @return the QName
     */
    public static QName constructQName(String namespaceURI, String localName, String prefix) {
        if (DataTypeHelper.isEmpty(prefix)) {
            return new QName(namespaceURI, localName);
        } else if (DataTypeHelper.isEmpty(namespaceURI)) {
            return new QName(localName);
        }

        return new QName(namespaceURI, localName, prefix);
    }

    /**
     * Constructs a QName from a string (attribute or element content) value.
     *
     * @param qname the QName string
     * @param owningObject XMLObject, with cached DOM, owning the QName
     *
     * @return the QName respresented by the string
     */
    public static QName constructQName(String qname, XMLObject owningObject) {
        return constructQName(qname, owningObject.getDOM());
    }

    /**
     * Constructs a QName from a string (attribute element content) value.
     *
     * @param qname the QName string
     * @param owningElement parent DOM element of the Node which contains the QName value
     *
     * @return the QName respresented by the string
     */
    public static QName constructQName(String qname, Element owningElement) {
        String nsURI;
        String nsPrefix;
        String name;

        if (qname.indexOf(":") > -1) {
            StringTokenizer qnameTokens = new StringTokenizer(qname, ":");
            nsPrefix = qnameTokens.nextToken();
            name = qnameTokens.nextToken();
        } else {
            nsPrefix = "";
            name = qname;
        }

        nsURI = lookupNamespaceURI(owningElement, nsPrefix);
        return constructQName(nsURI, name, nsPrefix);
    }

    /**
     * Constructs an element, rooted in the given document, with the given name.
     *
     * @param document the document containing the element
     * @param elementName the name of the element, must contain a local name, may contain a namespace URI and prefix
     *
     * @return the element
     */
    public static Element constructElement(Document document, QName elementName) {
        return constructElement(document, elementName.getNamespaceURI(), elementName.getLocalPart(), elementName
            .getPrefix());
    }

    /**
     * Constructs an element, rooted in the given document, with the given information.
     *
     * @param document the document containing the element
     * @param namespaceURI the URI of the namespace the element is in
     * @param localName the element's local name
     * @param prefix the prefix of the namespace the element is in
     *
     * @return the element
     */
    public static Element constructElement(Document document, String namespaceURI, String localName, String prefix) {
        String trimmedLocalName = DataTypeHelper.safeTrimOrNullString(localName);

        if (trimmedLocalName == null) {
            throw new IllegalArgumentException("Local name may not be null or empty");
        }

        String qualifiedName;
        String trimmedPrefix = DataTypeHelper.safeTrimOrNullString(prefix);
        if (trimmedPrefix != null) {
            qualifiedName = trimmedPrefix + ":" + DataTypeHelper.safeTrimOrNullString(trimmedLocalName);
        } else {
            qualifiedName = DataTypeHelper.safeTrimOrNullString(trimmedLocalName);
        }

        if (!DataTypeHelper.isEmpty(namespaceURI)) {
            return document.createElementNS(namespaceURI, qualifiedName);
        } else {
            return document.createElementNS(null, qualifiedName);
        }
    }

    /**
     * Appends the child Element to the parent Element, adopting the child Element into the parent's Document if needed.
     *
     * @param parentElement the parent Element
     * @param childElement the child Element
     */
    public static void appendChildElement(Element parentElement, Element childElement) {
        Document parentDocument = parentElement.getOwnerDocument();
        adoptElement(childElement, parentDocument);

        parentElement.appendChild(childElement);
    }

    /**
     * Adopts an element into a document if the child is not already in the document.
     *
     * @param adoptee the element to be adopted
     * @param adopter the document into which the element is adopted
     */
    public static void adoptElement(Element adoptee, Document adopter) {
        if (!(adoptee.getOwnerDocument().equals(adopter))) {
            if (adopter.adoptNode(adoptee) == null) {
                // This can happen if the adopter and adoptee were produced by different DOM implementations
                throw new XMLRuntimeException("DOM Element node adoption failed");
            }
        }
    }

    /**
     * Creates a text node with the given content and appends it as child to the given element.
     *
     * @param domElement the element to recieve the text node
     * @param textContent the content for the text node
     */
    public static void appendTextContent(Element domElement, String textContent) {
        if (textContent == null) {
            return;
        }
        Document parentDocument = domElement.getOwnerDocument();
        Text textNode = parentDocument.createTextNode(textContent);
        domElement.appendChild(textNode);
    }

    /**
     * Adds a namespace declaration (xmlns:) attribute to the given element.
     *
     * @param domElement the element to add the attribute to
     * @param namespaceURI the URI of the namespace
     * @param prefix the prefix for the namespace
     */
    public static void appendNamespaceDeclaration(Element domElement, String namespaceURI, String prefix) {
        String nsURI = DataTypeHelper.safeTrimOrNullString(namespaceURI);
        String nsPrefix = DataTypeHelper.safeTrimOrNullString(prefix);

        String attributeName;
        if (nsPrefix == null) {
            attributeName = XMLConstants.XMLNS_PREFIX;
        } else {
            attributeName = XMLConstants.XMLNS_PREFIX + ":" + nsPrefix;
        }

        String attributeValue;
        if (nsURI == null) {
            attributeValue = "";
        } else {
            attributeValue = nsURI;
        }

        domElement.setAttributeNS(XMLConstants.XMLNS_NS, attributeName, attributeValue);
    }

    /**
     * Looks up the namespace URI associated with the given prefix starting at the given element. This method differs
     * from the {@link Node#lookupNamespaceURI(java.lang.String)} in that it only those namespaces declared by an xmlns
     * attribute are inspected. The Node method also checks the namespace a particular node was created in by way of a
     * call like {@link Document#createElementNS(java.lang.String, java.lang.String)} even if the resulting element
     * doesn't have an namespace delcaration attribute.
     *
     * @param startingElement the starting element
     * @param prefix the prefix to look up
     *
     * @return the namespace URI for the given prefix
     */
    public static String lookupNamespaceURI(Element startingElement, String prefix) {
        return lookupNamespaceURI(startingElement, null, prefix);
    }

    /**
     * Looks up the namespace URI associated with the given prefix starting at the given element. This method differs
     * from the {@link Node#lookupNamespaceURI(java.lang.String)} in that it only those namespaces declared by an xmlns
     * attribute are inspected. The Node method also checks the namespace a particular node was created in by way of a
     * call like {@link Document#createElementNS(java.lang.String, java.lang.String)} even if the resulting element
     * doesn't have an namespace delcaration attribute.
     *
     * @param startingElement the starting element
     * @param stopingElement the ancestor of the starting element that serves as the upper-bound, inclusive, for the
     *            search
     * @param prefix the prefix to look up
     *
     * @return the namespace URI for the given prefer or null
     */
    public static String lookupNamespaceURI(Element startingElement, Element stopingElement, String prefix) {
        String namespaceURI;

        // This code is a modified version of the lookup code within Xerces
        if (startingElement.hasAttributes()) {
            NamedNodeMap map = startingElement.getAttributes();
            int length = map.getLength();
            for (int i = 0; i < length; i++) {
                Node attr = map.item(i);
                String attrPrefix = attr.getPrefix();
                String value = attr.getNodeValue();
                namespaceURI = attr.getNamespaceURI();
                if (namespaceURI != null && namespaceURI.equals(XMLConstants.XMLNS_NS)) {
                    // at this point we are dealing with DOM Level 2 nodes only
                    if (prefix == null && attr.getNodeName().equals(XMLConstants.XMLNS_PREFIX)) {
                        // default namespace
                        return value;
                    } else if (attrPrefix != null && attrPrefix.equals(XMLConstants.XMLNS_PREFIX)
                        && attr.getLocalName().equals(prefix)) {
                        // non default namespace
                        return value;
                    }
                }
            }
        }

        if (startingElement != stopingElement) {
            Element ancestor = getElementAncestor(startingElement);
            if (ancestor != null) {
                return lookupNamespaceURI(ancestor, stopingElement, prefix);
            }
        }

        return null;
    }

    /**
     * Looks up the namespace prefix associated with the given URI starting at the given element. This method differs
     * from the {@link Node#lookupPrefix(java.lang.String)} in that it only those namespaces declared by an xmlns
     * attribute are inspected. The Node method also checks the namespace a particular node was created in by way of a
     * call like {@link Document#createElementNS(java.lang.String, java.lang.String)} even if the resulting element
     * doesn't have an namespace delcaration attribute.
     *
     * @param startingElement the starting element
     * @param namespaceURI the uri to look up
     *
     * @return the prefix for the given namespace URI
     */
    public static String lookupPrefix(Element startingElement, String namespaceURI) {
        return lookupPrefix(startingElement, null, namespaceURI);
    }

    /**
     * Looks up the namespace prefix associated with the given URI starting at the given element. This method differs
     * from the {@link Node#lookupPrefix(java.lang.String)} in that it only those namespaces declared by an xmlns
     * attribute are inspected. The Node method also checks the namespace a particular node was created in by way of a
     * call like {@link Document#createElementNS(java.lang.String, java.lang.String)} even if the resulting element
     * doesn't have an namespace delcaration attribute.
     *
     * @param startingElement the starting element
     * @param stopingElement the ancestor of the starting element that serves as the upper-bound, inclusive, for the
     *            search
     * @param namespaceURI the uri to look up
     *
     * @return the prefix for the given namespace URI
     */
    public static String lookupPrefix(Element startingElement, Element stopingElement, String namespaceURI) {
        String namespace;

        // This code is a modified version of the lookup code within Xerces
        if (startingElement.hasAttributes()) {
            NamedNodeMap map = startingElement.getAttributes();
            int length = map.getLength();
            for (int i = 0; i < length; i++) {
                Node attr = map.item(i);
                String attrPrefix = attr.getPrefix();
                String value = attr.getNodeValue();
                namespace = attr.getNamespaceURI();
                if (namespace != null && namespace.equals(XMLConstants.XMLNS_NS)) {
                    // DOM Level 2 nodes
                    if (attr.getNodeName().equals(XMLConstants.XMLNS_PREFIX)
                        || (attrPrefix != null && attrPrefix.equals(XMLConstants.XMLNS_PREFIX))
                        && value.equals(namespaceURI)) {

                        String localname = attr.getLocalName();
                        String foundNamespace = startingElement.lookupNamespaceURI(localname);
                        if (foundNamespace != null && foundNamespace.equals(namespaceURI)) {
                            return localname;
                        }
                    }

                }
            }
        }

        if (startingElement != stopingElement) {
            Element ancestor = getElementAncestor(startingElement);
            if (ancestor != null) {
                return lookupPrefix(ancestor, stopingElement, namespaceURI);
            }
        }

        return null;
    }

    /**
     * Gets the child nodes with the given namespace qualified tag name. If you need to retrieve multiple, named,
     * children consider using {@link #getChildElements(Element)}.
     *
     * @param root element to retrieve the children from
     * @param namespaceURI namespace URI of the child element
     * @param localName local, tag, name of the child element
     *
     * @return list of child elements, never null
     */
    public static List<Element> getChildElementsByTagNameNS(Element root, String namespaceURI, String localName) {
        ArrayList<Element> children = new ArrayList<Element>();

        Element e = getFirstChildElement(root);
        while (e != null) {
            if (DataTypeHelper.safeEquals(e.getNamespaceURI(), namespaceURI)
                && DataTypeHelper.safeEquals(e.getLocalName(), localName)) {
                children.add(e);
            }

            e = getNextSiblingElement(e);
        }

        return children;
    }

    /**
     * Gets the child nodes with the given local tag name. If you need to retrieve multiple, named, children consider
     * using {@link #getChildElements(Element)}.
     *
     * @param root element to retrieve the children from
     * @param localName local, tag, name of the child element
     *
     * @return list of child elements, never null
     */
    public static List<Element> getChildElementsByTagName(Element root, String localName) {
        ArrayList<Element> children = new ArrayList<Element>();

        Element e = getFirstChildElement(root);
        while (e != null) {
            if (DataTypeHelper.safeEquals(e.getLocalName(), localName)) {
                children.add(e);
            }

            e = getNextSiblingElement(e);
        }

        return children;
    }

    /**
     * Gets the child elements of the given element in a single iteration.
     *
     * @param root element to get the child elements of
     *
     * @return child elements indexed by namespace qualifed tag name, never null
     */
    public static Map<QName, List<Element>> getChildElements(Element root) {
        Map<QName, List<Element>> children = new HashMap<QName, List<Element>>();

        Element e = getFirstChildElement(root);
        while (e != null) {
            QName qname = getNodeQName(e);
            List<Element> elements = children.get(qname);
            if (elements == null) {
                elements = new ArrayList<Element>();
                children.put(qname, elements);
            }

            elements.add(e);
            e = getNextSiblingElement(e);
        }

        return children;
    }

    /**
     * Gets the ancestor element node to the given node.
     *
     * @param currentNode the node to retrive the ancestor for
     *
     * @return the ancestral element node of the current node, or null
     */
    public static Element getElementAncestor(Node currentNode) {
        Node parent = currentNode.getParentNode();
        if (parent != null) {
            short type = parent.getNodeType();
            if (type == Node.ELEMENT_NODE) {
                return (Element) parent;
            }
            return getElementAncestor(parent);
        }
        return null;
    }

    /**
     * Converts a Node into a String using the DOM, level 3, Load/Save serializer.
     *
     * @param node the node to be written to a string
     *
     * @return the string representation of the node
     */
    public static String nodeToString(Node node) {
        StringWriter writer = new StringWriter();
        writeNode(node, writer);
        return writer.toString();
    }

    /**
     * Pretty prints the XML node.
     *
     * @param node xml node to print
     *
     * @return pretty-printed xml
     */
    public static String prettyPrintXML(Node node) {
        StringWriter writer = new StringWriter();
        writeNode(node, writer,  getPrettyPrintParams());
        return writer.toString();
    }

    /**
     * Create the parameters set used in pretty print formatting of an LSSerializer.
     *
     * @return the params map
     */
    private static Map<String, Object> getPrettyPrintParams() {
        if (prettyPrintParams == null) {
            prettyPrintParams = new LazyMap<String, Object>();
            prettyPrintParams.put("format-pretty-print", Boolean.TRUE);
        }
        return prettyPrintParams;
    }

    /**
     * Writes a Node out to a Writer using the DOM, level 3, Load/Save serializer. The written content is encoded using
     * the encoding specified in the writer configuration.
     *
     * @param node the node to write out
     * @param output the writer to write the XML to
     */
    public static void writeNode(Node node, Writer output) {
        writeNode(node, output, null);
    }

    /**
     * Writes a Node out to a Writer using the DOM, level 3, Load/Save serializer. The written content is encoded using
     * the encoding specified in the writer configuration.
     *
     * @param node the node to write out
     * @param output the writer to write the XML to
     * @param serializerParams parameters to pass to the {@link DOMConfiguration} of the serializer
     *         instance, obtained via {@link LSSerializer#getDomConfig()}. May be null.
     */
    public static void writeNode(Node node, Writer output, Map<String, Object> serializerParams) {
        DOMImplementationLS domImplLS = getLSDOMImpl(node);

        LSSerializer serializer = getLSSerializer(domImplLS, serializerParams);

        LSOutput serializerOut = domImplLS.createLSOutput();
        serializerOut.setCharacterStream(output);

        serializer.write(node, serializerOut);
    }

    /**
     * Writes a Node out to an OutputStream using the DOM, level 3, Load/Save serializer. The written content
     * is encoded using the encoding specified in the output stream configuration.
     *
     * @param node the node to write out
     * @param output the output stream to write the XML to
     */
    public static void writeNode(Node node, OutputStream output) {
        writeNode(node, output, null);
    }


    /**
     * Writes a Node out to an OutputStream using the DOM, level 3, Load/Save serializer. The written content
     * is encoded using the encoding specified in the output stream configuration.
     *
     * @param node the node to write out
     * @param output the output stream to write the XML to
     * @param serializerParams parameters to pass to the {@link DOMConfiguration} of the serializer
     *         instance, obtained via {@link LSSerializer#getDomConfig()}. May be null.
     */
    public static void writeNode(Node node, OutputStream output, Map<String, Object> serializerParams) {
        DOMImplementationLS domImplLS = getLSDOMImpl(node);

        LSSerializer serializer = getLSSerializer(domImplLS, serializerParams);

        LSOutput serializerOut = domImplLS.createLSOutput();
        serializerOut.setByteStream(output);

        serializer.write(node, serializerOut);
    }

    /**
     * Obtain a the DOM, level 3, Load/Save serializer {@link LSSerializer} instance from the
     * given {@link DOMImplementationLS} instance.
     *
     * <p>
     * The serializer instance will be configured with the parameters passed as the <code>serializerParams</code>
     * argument. It will also be configured with an {@link LSSerializerFilter} that shows all nodes to the filter,
     * and accepts all nodes shown.
     * </p>
     *
     * @param domImplLS the DOM Level 3 Load/Save implementation to use
     * @param serializerParams parameters to pass to the {@link DOMConfiguration} of the serializer
     *         instance, obtained via {@link LSSerializer#getDomConfig()}. May be null.
     *
     * @return a new LSSerializer instance
     */
    public static LSSerializer getLSSerializer(DOMImplementationLS domImplLS, Map<String, Object> serializerParams) {
        LSSerializer serializer = domImplLS.createLSSerializer();

        serializer.setFilter(new LSSerializerFilter() {

            public short acceptNode(Node arg0) {
                return FILTER_ACCEPT;
            }

            public int getWhatToShow() {
                return SHOW_ALL;
            }
        });


        if (serializerParams != null) {
            DOMConfiguration serializerDOMConfig = serializer.getDomConfig();
            for (String key : serializerParams.keySet()) {
                serializerDOMConfig.setParameter(key, serializerParams.get(key));
            }
        }

        return serializer;
    }

    /**
     * Get the DOM Level 3 Load/Save {@link DOMImplementationLS} for the given node.
     *
     * @param node the node to evaluate
     * @return the DOMImplementationLS for the given node
     */
    public static DOMImplementationLS getLSDOMImpl(Node node) {
        DOMImplementation domImpl;
        if (node instanceof Document) {
            domImpl = ((Document) node).getImplementation();
        } else {
            domImpl = node.getOwnerDocument().getImplementation();
        }

        DOMImplementationLS domImplLS = (DOMImplementationLS) domImpl.getFeature("LS", "3.0");
        return domImplLS;
    }

    /**
     * Converts a QName into a string that can be used for attribute values or element content.
     *
     * @param qname the QName to convert to a string
     *
     * @return the string value of the QName
     */
    public static String qnameToContentString(QName qname) {
        StringBuffer buf = new StringBuffer();

        String prefix = DataTypeHelper.safeTrimOrNullString(qname.getPrefix());
        if (prefix != null) {
            buf.append(prefix);
            buf.append(":");
        }
        buf.append(qname.getLocalPart());
        return buf.toString();
    }

    /**
     * Ensures that all the visibly used namespaces referenced by the given Element or its descendants are declared by
     * the given Element or one of its descendants.
     *
     * <strong>NOTE:</strong> This is a very costly operation.
     *
     * @param domElement the element to act as the root of the namespace declarations
     *
     * @throws XMLParserException thrown if a namespace prefix is encountered that can't be resolved to a namespace URI
     */
    public static void rootNamespaces(Element domElement) throws XMLParserException {
        rootNamespaces(domElement, domElement);
    }

    /**
     * Recursively called function that ensures all the visibly used namespaces referenced by the given Element or its
     * descendants are declared if they don't appear in the list of already resolved namespaces.
     *
     * @param domElement the Element
     * @param upperNamespaceSearchBound the "root" element of the fragment where namespaces may be rooted
     *
     * @throws XMLParserException thrown if a namespace prefix is encountered that can't be resolved to a namespace URI
     */
    private static void rootNamespaces(Element domElement, Element upperNamespaceSearchBound) throws XMLParserException {
        String namespaceURI = null;
        String namespacePrefix = domElement.getPrefix();

        // Check if the namespace for this element is already declared on this element
        boolean nsDeclaredOnElement = false;
        if (namespacePrefix == null) {
            nsDeclaredOnElement = domElement.hasAttributeNS(null, XMLConstants.XMLNS_PREFIX);
        } else {
            nsDeclaredOnElement = domElement.hasAttributeNS(XMLConstants.XMLNS_NS, namespacePrefix);
        }

        if (!nsDeclaredOnElement) {
            // Namspace for element was not declared on the element itself, see if the namespace is declared on
            // an ancestral element within the subtree where namespaces much be rooted
            namespaceURI = lookupNamespaceURI(domElement, upperNamespaceSearchBound, namespacePrefix);

            if (namespaceURI == null) {
                // Namespace for the element is not declared on any ancestral nodes within the subtree where namespaces
                // must be rooted. Resolve the namespace from ancestors outside that subtree.
                namespaceURI = lookupNamespaceURI(upperNamespaceSearchBound, null, namespacePrefix);
                if (namespaceURI != null) {
                    // Namespace resolved outside the subtree where namespaces must be declared so declare the namespace
                    // on this element (within the subtree).
                    appendNamespaceDeclaration(domElement, namespaceURI, namespacePrefix);
                } else {
                    // Namespace couldn't be resolved from any ancestor. If the namespace prefix is null then the
                    // element is simply in the undeclared default document namespace, which is fine. If it isn't null
                    // then a namespace prefix, that hasn't properly been declared, is being used.
                    if (namespacePrefix != null) {
                        throw new XMLParserException("Unable to resolve namespace prefix " + namespacePrefix
                                                         + " found on element " + getNodeQName(domElement));
                    }
                }
            }
        }

        // Make sure all the attribute URIs are rooted here or have been rooted in an ancestor
        NamedNodeMap attributes = domElement.getAttributes();
        Node attributeNode;
        for (int i = 0; i < attributes.getLength(); i++) {
            namespacePrefix = null;
            namespaceURI = null;
            attributeNode = attributes.item(i);

            // Shouldn't need this check, but just to be safe, we have it
            if (attributeNode.getNodeType() != Node.ATTRIBUTE_NODE) {
                continue;
            }

            namespacePrefix = attributeNode.getPrefix();
            if (!DataTypeHelper.isEmpty(namespacePrefix)) {
                // If it's the "xmlns" prefix then it is the namespace declaration,
                // don't try to look it up and redeclare it
                if (namespacePrefix.equals(XMLConstants.XMLNS_PREFIX)
                    || namespacePrefix.equals(XMLConstants.XML_PREFIX)) {
                    continue;
                }

                // check to see if the namespace for the prefix has already been defined within the XML fragment
                namespaceURI = lookupNamespaceURI(domElement, upperNamespaceSearchBound, namespacePrefix);
                if (namespaceURI == null) {
                    namespaceURI = lookupNamespaceURI(upperNamespaceSearchBound, null, namespacePrefix);
                    if (namespaceURI == null) {
                        throw new XMLParserException("Unable to resolve namespace prefix " + namespacePrefix
                                                         + " found on attribute " + getNodeQName(attributeNode) + " found on element "
                                                         + getNodeQName(domElement));
                    }

                    appendNamespaceDeclaration(domElement, namespaceURI, namespacePrefix);
                }
            }
        }

        // Now for the child elements, we pass a copy of the resolved namespace list in order to
        // maintain proper scoping of namespaces.
        Element childNode = getFirstChildElement(domElement);
        while (childNode != null) {
            rootNamespaces(childNode, upperNamespaceSearchBound);
            childNode = getNextSiblingElement(childNode);
        }
    }

    /**
     * Shortcut for checking a DOM element node's namespace and local name.
     *
     * @param e An element to compare against
     * @param ns An XML namespace to compare
     * @param localName A local name to compare
     * @return true iff the element's local name and namespace match the parameters
     */
    public static boolean isElementNamed(Element e, String ns, String localName) {
        return e != null && DataTypeHelper.safeEquals(ns, e.getNamespaceURI())
            && DataTypeHelper.safeEquals(localName, e.getLocalName());
    }

    /**
     * Gets the first child Element of the node, skipping any Text nodes such as whitespace.
     *
     * @param n The parent in which to search for children
     * @return The first child Element of n, or null if none
     */
    public static Element getFirstChildElement(Node n) {
        Node child = n.getFirstChild();
        while (child != null && child.getNodeType() != Node.ELEMENT_NODE) {
            child = child.getNextSibling();
        }

        if (child != null) {
            return (Element) child;
        } else {
            return null;
        }
    }

    /**
     * Gets the next sibling Element of the node, skipping any Text nodes such as whitespace.
     *
     * @param n The sibling to start with
     * @return The next sibling Element of n, or null if none
     */
    public static Element getNextSiblingElement(Node n) {
        Node sib = n.getNextSibling();
        while (sib != null && sib.getNodeType() != Node.ELEMENT_NODE) {
            sib = sib.getNextSibling();
        }

        if (sib != null) {
            return (Element) sib;
        } else {
            return null;
        }
    }

    /**
     * Converts a lexical duration, as defined by XML Schema 1.0, into milliseconds.
     *
     * @param duration lexical duration representation
     *
     * @return duration in milliseconds
     */
    public static long durationToLong(String duration) {
        Duration xmlDuration = getDataTypeFactory().newDuration(duration);
        return xmlDuration.getTimeInMillis(new GregorianCalendar());
    }

    /**
     * Converts a duration in milliseconds to a lexical duration, as defined by XML Schema 1.0.
     *
     * @param duration the duration
     *
     * @return the lexical representation
     */
    public static String longToDuration(long duration) {
        Duration xmlDuration = getDataTypeFactory().newDuration(duration);
        return xmlDuration.toString();
    }

}