/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.web;

import javax.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.config.ExternalProviderConfiguration;
import org.springframework.security.saml.config.SamlConfiguration;
import org.springframework.security.saml.init.Defaults;
import org.springframework.security.saml.init.SpringSecuritySaml;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;
import sample.config.AppConfig;

import static org.springframework.security.saml.init.Defaults.authenticationRequest;

@Controller
public class ServiceProviderController {

    private SpringSecuritySaml springSecuritySaml = SpringSecuritySaml.getInstance().init();
    private SamlConfiguration configuration;
    private Map<String, ExternalProviderConfiguration> byName = new HashMap();
    private Map<String, IdentityProviderMetadata> byEntityId = new HashMap();
    private Map<String, String> nameToEntityId = new HashMap();

    @Autowired
    public void setAppConfig(AppConfig config) {
        this.configuration = config;
        this.configuration.getServiceProvider().getProviders().stream().forEach(
            p -> {
                byName.put(p.getName(), p);
                IdentityProviderMetadata m = (IdentityProviderMetadata) springSecuritySaml.resolve(p.getMetadata(), null);
                byEntityId.put(m.getEntityId(), m);
                nameToEntityId.put(p.getName(), m.getEntityId());
            }
        );
    }

    @RequestMapping(value = {"/", "/index", "logged-in"})
    public String home() {
        return "logged-in";
    }

    @RequestMapping("/saml/sp/select")
    public String selectProvider(HttpServletRequest request, Model model) {
        List<ModelProvider> providers =
            configuration.getServiceProvider().getProviders().stream().map(
                p -> new ModelProvider().setLinkText(p.getLinktext()).setRedirect(getDiscoveryRedirect(request, p))
            )
            .collect(Collectors.toList());
        model.addAttribute("idps", providers);
        return "select-provider";
    }

    protected String getDiscoveryRedirect(HttpServletRequest request, ExternalProviderConfiguration p) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(getBasePath(request));
        builder.pathSegment("saml/sp/discovery");
        builder.queryParam("idp", nameToEntityId.get(p.getName()));
        return builder.build().toUriString();
    }

    @GetMapping(value = "/saml/sp/metadata", produces = MediaType.TEXT_XML_VALUE)
    public @ResponseBody()
    String metadata(HttpServletRequest request) {
        ServiceProviderMetadata metadata = getServiceProviderMetadata(request);
        return SpringSecuritySaml.getInstance().toXml(metadata);
    }

    @RequestMapping("/saml/sp/discovery")
    public View discovery(HttpServletRequest request,
                          @RequestParam(name = "idp", required = true) String idp) {
        //create authnrequest
        IdentityProviderMetadata m = byEntityId.get(idp);
        ServiceProviderMetadata local = getServiceProviderMetadata(request);
        AuthenticationRequest authenticationRequest = authenticationRequest(local, m);
        String url = getAuthnRequestRedirect(request, m, authenticationRequest);
        return new RedirectView(url);
    }

    @RequestMapping("/saml/sp/SSO")
    public View sso(HttpServletRequest request,
                      @RequestParam(name = "SAMLResponse", required = true) String response) {
        //receive assertion
        String xml = springSecuritySaml.decodeAndInflate(response);
        Response r = (Response) springSecuritySaml.resolve(xml, null);
        NameIdPrincipal principal = (NameIdPrincipal) r.getAssertions().get(0).getSubject().getPrincipal();
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(principal.getValue(), null, Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(token);
        RedirectView view = new RedirectView("/");
        view.setContextRelative(true);
        return view;
    }

    public static class ModelProvider {
        private String linkText;
        private String redirect;

        public String getLinkText() {
            return linkText;
        }

        public ModelProvider setLinkText(String linkText) {
            this.linkText = linkText;
            return this;
        }

        public String getRedirect() {
            return redirect;
        }

        public ModelProvider setRedirect(String redirect) {
            this.redirect = redirect;
            return this;
        }
    }

    protected String getAuthnRequestRedirect(HttpServletRequest request,
                                             IdentityProviderMetadata m,
                                             AuthenticationRequest authenticationRequest) {
        String xml = springSecuritySaml.toXml(authenticationRequest);
        String deflated = springSecuritySaml.deflateAndEncode(xml);
        Endpoint endpoint = m.getIdentityProvider().getSingleSignOnService().get(0);
        UriComponentsBuilder url = UriComponentsBuilder.fromUriString(endpoint.getLocation());
        url.queryParam("SAMLRequest", URLEncoder.encode(deflated));
        return url.build(true).toUriString();
    }

    protected ServiceProviderMetadata getServiceProviderMetadata(HttpServletRequest request) {
        String base = getBasePath(request);
        return Defaults.serviceProviderMetadata(base, null, null);
    }

    protected String getBasePath(HttpServletRequest request) {
        return request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
    }

}
