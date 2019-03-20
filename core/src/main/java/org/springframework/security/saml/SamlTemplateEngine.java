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

package org.springframework.security.saml;

import java.io.Writer;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

/**
 * Saml messages are often delivered using browser redirects.
 * This can be via 302 Location responses or via forms that are delivered
 * to the browser using HTML and Javascript.
 * A SamlTemplateEngine can help process HTML/Javascript templates
 */
public interface SamlTemplateEngine {

	/**
	 * Process a template and deliver the response
	 *
	 * @param request    the incoming HTTP request
	 * @param templateId the template to use
	 * @param model      the model with the data inputs
	 * @param out        a writer where the processed template will be written to
	 */
	void process(HttpServletRequest request,
				 String templateId,
				 Map<String, Object> model,
				 Writer out);

}
