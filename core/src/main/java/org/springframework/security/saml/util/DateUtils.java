/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.springframework.security.saml.util;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.springframework.security.saml.SamlException;

import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;

public class DateUtils {

	public static String toZuluTime(DateTime d) {
		return d.toString(zulu());
	}

	public static DateTimeFormatter zulu() {
		return ISODateTimeFormat.dateTime().withChronology(ISOChronology.getInstanceUTC());
	}

	public static DateTime fromZuluTime(String instant) {
		return zulu().parseDateTime(instant);
	}

	public static DateTime toDateTime(XMLGregorianCalendar calendar) {
		if (calendar == null) {
			return null;
		}
		return new DateTime(calendar.toGregorianCalendar());
	}

	public static XMLGregorianCalendar toXmlGregorianCalendar(DateTime date) {
		if (date == null) {
			return null;
		}
		try {
			DatatypeFactory df = DatatypeFactory.newInstance();
			return df.newXMLGregorianCalendar(date.toGregorianCalendar());
		} catch (DatatypeConfigurationException e) {
			throw new SamlException(e);
		}
	}
}
