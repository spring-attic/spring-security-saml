/*
 * Copyright 2010 Vladimir Schäfer
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

import org.opensaml.common.binding.SAMLMessageContext;
import org.springframework.security.core.Authentication;

/**
 * Logger implementation which ignores all values.
 *
 * @author Vladimir Schäfer
 */
public class SAMLEmptyLogger implements SAMLLogger {

    public void log(String operation, String result, SAMLMessageContext context) {
    }

    public void log(String operation, String result, SAMLMessageContext context, Exception e) {
    }

    public void log(String operation, String result, SAMLMessageContext context, Authentication a, Exception e) {
    }
    
}
