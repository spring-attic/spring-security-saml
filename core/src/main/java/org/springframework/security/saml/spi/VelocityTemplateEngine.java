/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.saml.spi;

import java.io.Writer;
import java.util.Map;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml.SamlTemplateEngine;

import org.apache.velocity.VelocityContext;
import org.apache.velocity.runtime.log.NullLogChute;

import static java.nio.charset.StandardCharsets.UTF_8;

public class VelocityTemplateEngine implements SamlTemplateEngine {

	private final boolean disableVelocityLog;

	public VelocityTemplateEngine() {
		this(true);
	}

	public VelocityTemplateEngine(boolean disableVelocityLog) {
		this.disableVelocityLog = disableVelocityLog;
	}


	@Override
	public void process(HttpServletRequest request,
						String templateId,
						Map<String, Object> model,
						Writer out
	) {
		org.apache.velocity.app.VelocityEngine velocityEngine = newVelocityEngine();
		initializeVelocityEngine(velocityEngine);
		VelocityContext context = new VelocityContext();
		model.entrySet().stream().forEach(
			e -> context.put(e.getKey(), e.getValue())
		);

		velocityEngine.mergeTemplate(templateId, UTF_8.name(), context, out);
	}

	private org.apache.velocity.app.VelocityEngine newVelocityEngine() {
		return newVelocityEngine(getDefaultProperties());
	}

	protected void initializeVelocityEngine(org.apache.velocity.app.VelocityEngine velocityEngine) {
		if (disableVelocityLog) {
			velocityEngine.setProperty("runtime.log.logsystem.class", NullLogChute.class.getName());
		}
		velocityEngine.init();
	}

	private org.apache.velocity.app.VelocityEngine newVelocityEngine(final Properties props) {
		final org.apache.velocity.app.VelocityEngine engine = new org.apache.velocity.app.VelocityEngine();
		engine.init(props);
		return engine;
	}

	private Properties getDefaultProperties() {
		final Properties props = new Properties();
		props.setProperty(
			"string.resource.loader.class",
			"org.apache.velocity.runtime.resource.loader.StringResourceLoader"
		);
		props.setProperty(
			"classpath.resource.loader.class",
			"org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader"
		);
		props.setProperty("resource.loader", "classpath, string");
		return props;
	}

}
