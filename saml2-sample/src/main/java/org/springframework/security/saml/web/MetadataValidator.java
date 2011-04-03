/* Copyright 2011 Vladimir Schafer
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
package org.springframework.security.saml.web;

import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

/**
 * Validator for metadata from.
 */
public class MetadataValidator implements Validator {

    MetadataManager manager;

    public MetadataValidator(MetadataManager manager) {
        this.manager = manager;
    }

    public boolean supports(Class<?> clazz) {
        return clazz.equals(MetadataForm.class);
    }

    public void validate(Object target, Errors errors) {

        MetadataForm metadata = (MetadataForm) target;

        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "entityId", "required", "Entity id must be set.");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "alias", "required", "Alias must be set.");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "baseURL", "required", "Base URL is required.");

        if (metadata.getSecurityProfile() == null) {
            errors.rejectValue("securityProfile", null, "Security profile must be specified");
        } else if (!"pkix".equalsIgnoreCase(metadata.getSecurityProfile()) && !"metaiop".equals(metadata.getSecurityProfile())) {
            errors.rejectValue("securityProfile", null, "Selected value is not supported");
        }

        try {
            if (!errors.hasErrors() && metadata.isStore()) {
                EntityDescriptor entityDescriptor = manager.getEntityDescriptor(metadata.getEntityId());
                if (entityDescriptor != null) {
                    errors.rejectValue("entityId", null, "Selected entity ID is already used");
                }
                String idForAlias = manager.getEntityIdForAlias(metadata.getAlias());
                if (idForAlias != null) {
                    errors.rejectValue("alias", null, "Selected alias is already used");
                }
            }
        } catch (MetadataProviderException e) {
            throw new RuntimeException("Error loading alias data", e);
        }

    }

}
