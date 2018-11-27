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
package sample;

import java.util.Arrays;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

@SpringBootApplication
public class SimpleServiceProviderApplication {

	public static void main(String[] args) {
		SpringApplication.run(SimpleServiceProviderApplication.class, args);
	}

	public static class JavaOnlyConditionExample extends SpringBootCondition {
		@Override
		public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
			String[] profiles = context.getEnvironment().getActiveProfiles();
			if (profiles!=null && profiles.length==1 && "sample.profile.java".equals(profiles[0])) {
				return ConditionOutcome.match();
			}
			else {
				return ConditionOutcome.noMatch("Java Only Profile is not enabled:"+ Arrays.toString(profiles));
			}
		}
	}

	public static class BeanConfigurationConditionExample extends SpringBootCondition {
		@Override
		public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
			return ConditionOutcome.inverse(
				new JavaOnlyConditionExample().getMatchOutcome(context, metadata)
			);
		}
	}
}
