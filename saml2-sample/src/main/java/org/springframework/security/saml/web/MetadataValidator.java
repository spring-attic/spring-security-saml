package org.springframework.security.saml.web;

import org.opensaml.saml2.metadata.EntityDescriptor;
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
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "entityId", "required", "Entity id must be set.");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "alias", "required", "Alias must be set.");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "baseURL", "required", "Base URL is required.");
    }

}
