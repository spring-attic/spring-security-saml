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
package sample.web;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.config.ExternalProviderConfiguration;
import org.springframework.security.saml.config.SamlConfiguration;
import org.springframework.security.saml.init.Defaults;
import org.springframework.security.saml.init.SpringSecuritySaml;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import sample.config.AppConfig;

import static org.springframework.security.saml.init.Defaults.assertion;

@Controller
public class IdentityProviderController {

    private SpringSecuritySaml springSecuritySaml = SpringSecuritySaml.getInstance().init();
    private SamlConfiguration configuration;
    private Map<String, ExternalProviderConfiguration> byName = new HashMap();
    private Map<String, ServiceProviderMetadata> byEntityId = new HashMap();
    private Map<String, String> nameToEntityId = new HashMap();

    @Autowired
    public void setAppConfig(AppConfig config) {
        this.configuration = config;
        this.configuration.getIdentityProvider().getServiceProviders().stream().forEach(
            p -> {
                byName.put(p.getName(), p);
                ServiceProviderMetadata m = (ServiceProviderMetadata) springSecuritySaml.resolve(p.getMetadata(), null);
                byEntityId.put(m.getEntityId(), m);
                nameToEntityId.put(p.getName(), m.getEntityId());
            }
        );
    }


    @GetMapping(value = "/saml/idp/metadata", produces = MediaType.TEXT_XML_VALUE)
    public @ResponseBody()
    String metadata(HttpServletRequest request) {
        IdentityProviderMetadata metadata = getIdentityProviderMetadata(request);
        return SpringSecuritySaml.getInstance().toXml(metadata);
    }

    protected IdentityProviderMetadata getIdentityProviderMetadata(HttpServletRequest request) {
        String base = getBasePath(request);
        return Defaults.identityProviderMetadata(base, null, null);
    }

    @RequestMapping("/saml/idp/SSO")
    public String authenticationRequest(HttpServletRequest request,
                                        Model model,
                                        @RequestParam(name = "SAMLRequest", required = true) String authn) {
        //receive AuthnRequest
        String xml = springSecuritySaml.decodeAndInflate(authn);
        AuthenticationRequest authenticationRequest = (AuthenticationRequest) springSecuritySaml.resolve(xml, null);
        Issuer issuer = authenticationRequest.getIssuer();
        ServiceProviderMetadata metadata = byEntityId.get(issuer.getValue());
        IdentityProviderMetadata local = getIdentityProviderMetadata(request);
        Assertion assertion = assertion(metadata, local, authenticationRequest);
        NameIdPrincipal principal = (NameIdPrincipal)assertion.getSubject().getPrincipal();
        principal.setValue(SecurityContextHolder.getContext().getAuthentication().getName());
        principal.setFormat(NameId.PERSISTENT);
        Response response = Defaults.response(authenticationRequest.getId(),
                                              assertion,
                                              metadata,
                                              local
        );

        String encoded = springSecuritySaml.deflateAndEncode(springSecuritySaml.toXml(response));
        model.addAttribute("url", authenticationRequest.getAssertionConsumerService().getLocation());
        model.addAttribute("SAMLResponse", encoded);
        return "saml-post";
    }

    protected String getBasePath(HttpServletRequest request) {
        return request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
    }
}
