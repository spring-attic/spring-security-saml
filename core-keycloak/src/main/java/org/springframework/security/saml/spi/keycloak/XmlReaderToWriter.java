/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.spi.keycloak;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.stream.events.XMLEvent;

/*
 * Copy from
 * https://github.com/coheigea/testcases/blob/ceead14f5a047369be8fc865ab027b492ae7efda/apache/santuario/santuario-xml-signature/src/test/java/org/apache/coheigea/santuario/xmlsignature/XmlReaderToWriter.java
 */

class XmlReaderToWriter {
	private XmlReaderToWriter() {
	}

	static void writeAll(XMLStreamReader xmlr, XMLStreamWriter writer)
		throws XMLStreamException {
		while (xmlr.hasNext()) {
			xmlr.next();
			write(xmlr, writer);
		}
		//write(xmlr, writer); // write the last element
		writer.flush();
	}

	static void write(XMLStreamReader xmlr, XMLStreamWriter writer) throws XMLStreamException {
		switch (xmlr.getEventType()) {
			case XMLEvent.START_ELEMENT:
				final String localName = xmlr.getLocalName();
				final String namespaceURI = xmlr.getNamespaceURI();
				if (namespaceURI != null && namespaceURI.length() > 0) {
					final String prefix = xmlr.getPrefix();
					if (prefix != null)
						writer.writeStartElement(prefix, localName, namespaceURI);
					else
						writer.writeStartElement(namespaceURI, localName);
				} else {
					writer.writeStartElement(localName);
				}

				for (int i = 0, len = xmlr.getNamespaceCount(); i < len; i++) {
					String prefix = xmlr.getNamespacePrefix(i);
					if (prefix == null) {
						writer.writeDefaultNamespace(xmlr.getNamespaceURI(i));
					} else {
						writer.writeNamespace(prefix, xmlr.getNamespaceURI(i));
					}
				}

				for (int i = 0, len = xmlr.getAttributeCount(); i < len; i++) {
					final String attUri = xmlr.getAttributeNamespace(i);

					if (attUri != null && attUri.length() > 0) {
						final String prefix = xmlr.getAttributePrefix(i);
						if (prefix != null)
							writer.writeAttribute(prefix, attUri, xmlr.getAttributeLocalName(i), xmlr.getAttributeValue(i));
						else
							writer.writeAttribute(attUri, xmlr.getAttributeLocalName(i), xmlr.getAttributeValue(i));
					} else {
						writer.writeAttribute(xmlr.getAttributeLocalName(i), xmlr.getAttributeValue(i));
					}

				}
				break;
			case XMLEvent.END_ELEMENT:
				writer.writeEndElement();
				break;
			case XMLEvent.SPACE:
			case XMLEvent.CHARACTERS:
				char[] text = new char[xmlr.getTextLength()];
				xmlr.getTextCharacters(0, text, 0, xmlr.getTextLength());
				writer.writeCharacters(text, 0, text.length);
				break;
			case XMLEvent.PROCESSING_INSTRUCTION:
				writer.writeProcessingInstruction(xmlr.getPITarget(), xmlr.getPIData());
				break;
			case XMLEvent.CDATA:
				writer.writeCData(xmlr.getText());
				break;
			case XMLEvent.COMMENT:
				writer.writeComment(xmlr.getText());
				break;
			case XMLEvent.ENTITY_REFERENCE:
				writer.writeEntityRef(xmlr.getLocalName());
				break;
			case XMLEvent.START_DOCUMENT:
				String encoding = xmlr.getCharacterEncodingScheme();
				String version = xmlr.getVersion();

				if (encoding != null && version != null)
					writer.writeStartDocument(encoding, version);
				else if (version != null)
					writer.writeStartDocument(xmlr.getVersion());
				break;
			case XMLEvent.END_DOCUMENT:
				writer.writeEndDocument();
				break;
			case XMLEvent.DTD:
				writer.writeDTD(xmlr.getText());
				break;
		}
	}
}
