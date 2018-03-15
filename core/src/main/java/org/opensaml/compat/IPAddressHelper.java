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

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Helper class for working with IP address data. */
public final class IPAddressHelper {

    /** Constructor. */
    private IPAddressHelper() {

    }

    /**
     * Convert the byte array representation of an IP address into a string.  Supports IPv4 and IPv6 addresses.
     * Supports optional subnet mask stored within the same byte array.  If the latter is present,
     * output will be: "ipAddr/mask".
     *
     * @param address IP address in byte array form (in network byte order)
     * @return IP address as a string, or null if can not be processed
     */
    public static String addressToString(byte[] address) {
        Logger log = getLogger();
        if (isIPv4(address)) {
            return ipv4ToString(address);
        } else if (isIPv6(address)) {
            return ipv6ToString(address);
        } else {
            log.error("IP address byte array was an invalid length: {}", address.length);
            return null;
        }
    }

    /**
     * Convert the byte array representation of an IPv4 address into a string.
     * Supports optional subnet mask stored within the same byte array.  If the latter is present,
     * output will be: "ipAddr/mask".
     *
     * @param address IP address in byte array form (in network byte order)
     * @return IP address as a string, or null if can not be processed
     */
    private static String ipv4ToString(byte[] address) {
        Logger log = getLogger();
        // This code was modeled after similar code in Sun's sun.security.x509.IPAddressName,
        // used by sun.security.x509.X509CertImpl.
        StringBuilder builder = new StringBuilder();
        byte[] ip = new byte[4];
        System.arraycopy(address, 0, ip, 0, 4);
        try {
            builder.append(InetAddress.getByAddress(ip).getHostAddress());
        } catch (UnknownHostException e) {
            // Thrown if address is illegal length.
            // Can't happen, we know that address is the right length.
            log.error("Unknown host exception processing IP address byte array: {}", e.getMessage());
            return null;
        }

        if(hasMask(address)) {
            byte[] mask = new byte[4];
            System.arraycopy(address, 4, mask, 0, 4);
            builder.append("/");
            try {
                builder.append(InetAddress.getByAddress(mask).getHostAddress());
            } catch (UnknownHostException e) {
                // Thrown if address is illegal length.
                // Can't happen, we know that address is the right length.
                log.error("Unknown host exception processing IP address byte array: {}", e.getMessage());
                return null;
            }
        }
        return builder.toString();
    }

    /**
     * Convert the byte array representation of an IPv6 address into a string.
     * Supports optional subnet mask stored within the same byte array.  If the latter is present,
     * output will be: "ipAddr/mask".
     *
     * @param address IP address in byte array form (in network byte order)
     * @return IP address as a string, or null if can not be processed
     */
    private static String ipv6ToString(byte[] address) {
        Logger log = getLogger();
        // This code was modeled after similar code in Sun's sun.security.x509.IPAddressName,
        // used by sun.security.x509.X509CertImpl.
        StringBuilder builder = new StringBuilder();
        byte[] ip = new byte[16];
        System.arraycopy(address, 0, ip, 0, 16);
        try {
            builder.append(InetAddress.getByAddress(ip).getHostAddress());
        } catch (UnknownHostException e) {
            // Thrown if address is illegal length.
            // Can't happen, we know that address is the right length.
            log.error("Unknown host exception processing IP address byte array: {}", e.getMessage());
            return null;
        }

        if(hasMask(address)) {
            log.error("IPv6 subnet masks are currently unsupported");
            return null;
            /*
            byte[] mask = new byte[16];
            for(int i = 16; i < 32; i++) {
                mask[i - 16] = address[i];
            }

            // TODO need to process bitmask array
            // to determine and validate subnet mask
            BitArray bitarray = new BitArray(128, mask);
            int j;
            for (j = 0; j < 128 && bitarray.get(j); j++);
            builder.append("/");
            builder.append(j).toString();
            for (; j < 128; j++) {
                if (bitarray.get(j)) {
                    log.error("Invalid IPv6 subdomain: set bit " + j + " not contiguous");
                    return null;
                }
            }
            */
        }
        return builder.toString();
    }


    /**
     * Check whether IP address array is IPv4.
     *
     * @param address IP address byte array
     * @return true if IPv4, false otherwise
     */
    public static boolean isIPv4(byte[] address) {
        return address.length == 4 || address.length == 8;
    }

    /**
     * Check whether IP address array is IPv6.
     *
     * @param address IP address byte array
     * @return true if IPv6, false otherwise
     */
    public static boolean isIPv6(byte[] address) {
        return address.length == 16 || address.length == 32;
    }

    /**
     * Check whether IP address array has a subnet mask or not.
     *
     * @param address IP address byte array
     * @return true if has subnet mask, false otherwise
     */
    public static boolean hasMask(byte[] address) {
        return address.length == 8 || address.length == 32;
    }

    /**
     * Get an SLF4J Logger.
     *
     * @return a Logger instance
     */
    private static Logger getLogger() {
        return LoggerFactory.getLogger(IPAddressHelper.class);
    }

}