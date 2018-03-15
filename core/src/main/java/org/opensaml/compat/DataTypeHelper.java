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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.StringTokenizer;

/** Helper class for working with various datatypes. */
public class DataTypeHelper {

    /** Constructor. */
    private DataTypeHelper() {

    }

    /**
     * A "safe" null/empty check for strings.
     *
     * @param s The string to check
     *
     * @return true if the string is null or the trimmed string is length zero
     */
    public static boolean isEmpty(String s) {
        if (s != null) {
            String sTrimmed = s.trim();
            if (sTrimmed.length() > 0) {
                return false;
            }
        }

        return true;
    }

    /**
     * Compares two strings for equality, allowing for nulls.
     *
     * @param <T> type of object to compare
     * @param s1 The first operand
     * @param s2 The second operand
     *
     * @return true if both are null or both are non-null and the same strng value
     */
    public static <T> boolean safeEquals(T s1, T s2) {
        if (s1 == null || s2 == null) {
            return s1 == s2;
        }

        return s1.equals(s2);
    }

    /**
     * A safe string trim that handles nulls.
     *
     * @param s the string to trim
     *
     * @return the trimmed string or null if the given string was null
     */
    public static String safeTrim(String s) {
        if (s != null) {
            return s.trim();
        }

        return null;
    }

    /**
     * Removes preceeding or proceeding whitespace from a string or return null if the string is null or of zero length
     * after trimming (i.e. if the string only contained whitespace).
     *
     * @param s the string to trim
     *
     * @return the trimmed string or null
     */
    public static String safeTrimOrNullString(String s) {
        if (s != null) {
            String sTrimmed = s.trim();
            if (sTrimmed.length() > 0) {
                return sTrimmed;
            }
        }

        return null;
    }

    /**
     * Converts an integer into an unsigned 4-byte array.
     *
     * @param integer integer to convert
     *
     * @return 4-byte array representing integer
     */
    public static byte[] intToByteArray(int integer) {
        byte[] intBytes = new byte[4];
        intBytes[0] = (byte) ((integer & 0xff000000) >>> 24);
        intBytes[1] = (byte) ((integer & 0x00ff0000) >>> 16);
        intBytes[2] = (byte) ((integer & 0x0000ff00) >>> 8);
        intBytes[3] = (byte) ((integer & 0x000000ff));

        return intBytes;
    }

    /**
     * Reads the contents of a file in to a byte array.
     *
     * @param file file to read
     * @return the byte contents of the file
     *
     * @throws IOException throw if there is a problem reading the file in to the byte array
     */
    public static byte[] fileToByteArray(File file) throws IOException {
        long numOfBytes = file.length();

        if (numOfBytes > Integer.MAX_VALUE) {
            throw new IOException("File is to large to be read in to a byte array");
        }

        byte[] bytes = new byte[(int) numOfBytes];
        FileInputStream ins = new FileInputStream(file);
        int offset = 0;
        int numRead = 0;
        do {
            numRead = ins.read(bytes, offset, bytes.length - offset);
            offset += numRead;
        } while (offset < bytes.length && numRead >= 0);

        if (offset < bytes.length) {
            throw new IOException("Could not completely read file " + file.getName());
        }

        ins.close();
        return bytes;
    }

    /**
     * Reads an input stream into a string. The provide stream is <strong>not</strong> closed.
     *
     * @param input the input stream to read
     * @param decoder character decoder to use, if null, system default character set is used
     *
     * @return the string read from the stream
     *
     * @throws IOException thrown if there is a problem reading from the stream and decoding it
     */
    public static String inputstreamToString(InputStream input, CharsetDecoder decoder) throws IOException {
        CharsetDecoder charsetDecoder = decoder;
        if (decoder == null) {
            charsetDecoder = Charset.defaultCharset().newDecoder();
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(input, charsetDecoder));

        StringBuilder stringBuffer = new StringBuilder();
        String line = reader.readLine();
        while(line != null){
            stringBuffer.append(line).append("\n");
            line = reader.readLine();
        }

        reader.close();

        return stringBuffer.toString();
    }

    /**
     * Converts a delimited string into a list.
     *
     * @param string the string to be split into a list
     * @param delimiter the delimiter between values. This string may contain
     *                  multiple delimiter characters, as allowed by
     *                  {@link StringTokenizer}
     *
     * @return the list of values or an empty list if the given string is null or empty
     */
    public static List<String> stringToList(String string, String delimiter) {
        if (delimiter == null) {
            throw new IllegalArgumentException("String delimiter may not be null");
        }

        ArrayList<String> values = new ArrayList<String>();

        String trimmedString = safeTrimOrNullString(string);
        if (trimmedString != null) {
            StringTokenizer tokens = new StringTokenizer(trimmedString, delimiter);
            while (tokens.hasMoreTokens()) {
                values.add(tokens.nextToken());
            }
        }

        return values;
    }

    /**
     * Converts a List of strings into a single string, with values separated by a
     * specified delimiter.
     *
     * @param values list of strings
     * @param delimiter the delimiter used between values
     *
     * @return delimited string of values
     */
    public static String listToStringValue(List<String> values, String delimiter) {
        if (delimiter == null) {
            throw new IllegalArgumentException("String delimiter may not be null");
        }

        StringBuilder stringValue = new StringBuilder();
        Iterator<String> valueItr = values.iterator();
        while(valueItr.hasNext()){
            stringValue.append(valueItr.next());
            if(valueItr.hasNext()){
                stringValue.append(delimiter);
            }
        }

        return stringValue.toString();
    }
}