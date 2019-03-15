/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.samples;import org.springframework.security.saml.key.KeyType;
import org.springframework.security.saml.key.SimpleKey;

public class SimpleSamlPhpTestKeys {
	public static SimpleKey getSimpleSamlPhpKeyData() {
		return new SimpleKey(
			"simplesamlphp-key",
			"-----BEGIN RSA PRIVATE KEY-----\n" +
				"MIIEowIBAAKCAQEAuHJ+thNcS6qTd+D5m6ygW5DlxY81oCfW/qV7mkX7egN9/bri\n" +
				"EHqHh+ankikVU5d9i9IHc9mYry8GV1vnKr37VVtbbxB78yRcsXk1t3wlHgkLHmy5\n" +
				"wNqkWtO0ZMU6OjX9uOJllkQ6HXKBxHw1Em8X02eiBMUqI0iFNkZw+lpZWFhXQ9Rh\n" +
				"aQSTpkAfKwHPMCSAXRxXUJ1/E7Ze4Weq7YKhGDM2FTLidhdq9R0lNc0gL8KXWD+q\n" +
				"0RhUSRH3QPZpt1inzS0nOXJY89F/018tL1ZQFfeZfanHxcz5q5DSLLfRWUsKbweP\n" +
				"S8gFZHtOBUDz8C4FR+IKYYiR9472eyPieZUvFQIDAQABAoIBAQCssQZSEu5nKd3I\n" +
				"b6tERewdzxxSTDM5MBPrd6SyXLOHGZ3s4fym0RHz+9EI185P5ZZ2Qr8XiLOb0btu\n" +
				"L23QZu/aix6gbh6fF3xx7bqNgH6AEJeIdOO13P/kyjIr5z0NI1/aqp3Sgy6mQ3+c\n" +
				"J27JQ5pbJLxdGvzI7C1NE8bTn6PnQbeeRVtdXBqsWcIUuRp6/nG8NzpB89t2/YBD\n" +
				"rfan8D1XqXsrG5pvRY1PpOMlWu6wDcXG81W+mOxgiE3trYL7xB5owfQS5lqx95md\n" +
				"wH9e2FP4jek66T3eko90KEvtsBrQHh21LNwiibu2yB3I+KaGpeiofOdfUvnqyU7a\n" +
				"kPDNGYhBAoGBAON4S2AD2lLnhZHX4fSv+wpR+uN+glB91XYs8FF4tun3YYVfyP6L\n" +
				"esy31NpoBB1NtiwRAlkBrQBZvJL9D8z5/qo2kd3utpeTyJUmG55CInc6A2ds7buI\n" +
				"xeS4ErZUyUD7XhRBoGVZeaPQ2kmTqmHext16l7kNVRjFufBuRWCT7QNXAoGBAM+U\n" +
				"z1LSvkdilxzI1MJRmPQHn0GEWJsl9k5/zhYCr2PJaQJDK4Tyjjau0jGHPBPb/Ruw\n" +
				"NHSDl71u0DmEmqTYSlPp6d5VGn0eReGTdG8Wfaox259wDGHq2io3rrR75S7Wx3SH\n" +
				"NY97MXvxM5bUbGJoqi3RAVtKeocFoLchoWFlcmlzAoGAHwzirR6ZhMuZzgi8DVyg\n" +
				"Vg5OwxMX0sj6hIEp5NUnktRz+XLTyvtbLerCIXYlaaKcBXPk8CVsainVtfLZX0+Y\n" +
				"1b9RNgxJ3HMN5F4pUvcQIVpH8KxL31eSO+BsnXsBZd9qPjWfIXaPRi9SPMztayKv\n" +
				"3rfHUjlhrln/QbSrv70xk00CgYBcVFY7Ap275rBMD1AC9oRP1qwRWiqHJ8V8eQBT\n" +
				"bfJRMh7Q8MuEoNZ8oBnCCeLA+pKEJEXQpU9y5L0dOEwIkmPNGzf4umXDzRlMEmgx\n" +
				"mRFgCDklm5MGYo2TRZ0hjhIMWV/yBsnd/e+ur0RBDE8BHojDRDmUP3ZsZCZuDjlX\n" +
				"tuXC3QKBgAjrT56tRcWsvNFGAX+K0Pmyfcl9bpQfFiK3ntYQ+zh0gdpUR8a1WFq4\n" +
				"Ja075Iety4MfhHLE1e/PDrLwFXzz8wWa5/EnQ5UKmpTMVAWBBcJ7GA93EPMjlJ4o\n" +
				"xVQuMTXHQ7/DiKlYEpOCisVOQLIWgMZOjKMfrvAnNngCtdh9d4vv\n" +
				"-----END RSA PRIVATE KEY-----\n",
			"-----BEGIN CERTIFICATE-----\n" +
				"MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYD\n" +
				"VQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYD\n" +
				"VQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwX\n" +
				"c2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0Bw\n" +
				"aXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJ\n" +
				"BgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAa\n" +
				"BgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQD\n" +
				"DBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlr\n" +
				"QHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62\n" +
				"E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz\n" +
				"2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWW\n" +
				"RDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQ\n" +
				"nX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5\n" +
				"cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gph\n" +
				"iJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5\n" +
				"ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTAD\n" +
				"AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduO\n" +
				"nRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+v\n" +
				"ZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLu\n" +
				"xbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6z\n" +
				"V9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3\n" +
				"lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk\n" +
				"-----END CERTIFICATE-----",
			"",
			KeyType.SIGNING
		);
	}

}
