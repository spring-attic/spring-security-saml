/*
 * Copyright 2010 Vladimir Sch�fer
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
package org.springframework.security.saml.log;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml.context.SAMLMessageContext;

/**
 * Implementations are supposed to log significant SAML operations.
 *
 * @author Vladimir Sch�fer
 */
public interface SAMLLogger {

    void log(String operation, String result, SAMLMessageContext context);
    void log(String operation, String result, SAMLMessageContext context, Exception e);
    void log(String operation, String result, SAMLMessageContext context, Authentication a, Exception e);

}
