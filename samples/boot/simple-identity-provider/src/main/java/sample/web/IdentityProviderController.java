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
import java.util.LinkedList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.MetadataResolver;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.config.ExternalProviderConfiguration;
import org.springframework.security.saml.config.SamlServerConfiguration;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.authentication.Status;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.Defaults;
import org.springframework.security.saml.util.Network;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.UriComponentsBuilder;
import sample.config.AppConfig;

import static org.springframework.http.HttpMethod.GET;

@Controller
public class IdentityProviderController {

    private SamlServerConfiguration configuration;
    private SamlTransformer transformer;
    private Defaults defaults;
    private MetadataResolver resolver;
    private Network network;

    @Autowired
    public IdentityProviderController setNetwork(Network network) {
        this.network = network;
        return this;
    }

    @Autowired
    public void setTransformer(SamlTransformer transformer) {
        this.transformer = transformer;
    }

    @Autowired
    public void setDefaults(Defaults defaults) {
        this.defaults = defaults;
    }

    @Autowired
    public void setMetadataResolver(MetadataResolver resolver) {
        this.resolver = resolver;
    }

    @Autowired
    public void setAppConfig(AppConfig config) {
        this.configuration = config;
    }


    @GetMapping(value = "/saml/idp/metadata", produces = MediaType.TEXT_XML_VALUE)
    public @ResponseBody()
    String metadata(HttpServletRequest request) {
        IdentityProviderMetadata metadata = getIdentityProviderMetadata(request);
        return transformer.toXml(metadata);
    }

    @RequestMapping(value = {"/saml/idp/select", "/"})
    public String selectProvider(HttpServletRequest request, Model model) {
        List<ModelProvider> providers = new LinkedList<>();
        configuration.getIdentityProvider().getProviders().stream().forEach(
            p -> {
                try {
                    ModelProvider mp = new ModelProvider().setLinkText(p.getLinktext()).setRedirect(getIdpInitUrl(request, p));
                    providers.add(mp);
                } catch (Exception x) {
                    x.printStackTrace();
                }
            }
        );
        model.addAttribute("sps", providers);
        return "select-provider";
    }

    @RequestMapping(value = {"/saml/idp/init"})
    public String idpInitiate(HttpServletRequest request,
                              Model model,
                              @RequestParam(name = "sp", required = true) String entityId) {
        //no authnrequest provided
        ServiceProviderMetadata metadata = resolver.resolveServiceProvider(entityId);
        IdentityProviderMetadata local = getIdentityProviderMetadata(request);
        String principal = SecurityContextHolder.getContext().getAuthentication().getName();
        Assertion assertion = getDefaults().assertion(metadata, local, null, principal, NameId.PERSISTENT);
        assertion.setSigningKey(local.getSigningKey(), local.getAlgorithm(), local.getDigest());
        Response response = getDefaults().response(null,
                                                   assertion,
                                                   metadata,
                                                   local
        );
        response.setSigningKey(local.getSigningKey(), local.getAlgorithm(), local.getDigest());
        response.setStatus(new Status().setCode(StatusCode.SUCCESS));
        String encoded = transformer.samlEncode(transformer.toXml(response), false);
        model.addAttribute("url", getAcs(metadata));
        model.addAttribute("SAMLResponse", encoded);
        return "saml-post";
    }

    @RequestMapping("/saml/idp/SSO")
    public String authenticationRequest(HttpServletRequest request,
                                        Model model,
                                        @RequestParam(name = "SAMLRequest", required = true) String authn) {
        //receive AuthnRequest
        String xml = transformer.samlDecode(authn, GET.matches(request.getMethod()));
        AuthenticationRequest authenticationRequest = (AuthenticationRequest) transformer.resolve(xml, null);
        ServiceProviderMetadata metadata = resolver.resolveServiceProvider(authenticationRequest);
        //validate the signatures
        authenticationRequest = (AuthenticationRequest) transformer.resolve(xml, metadata.getServiceProvider().getKeys());

        IdentityProviderMetadata local = getIdentityProviderMetadata(request);
        String principal = SecurityContextHolder.getContext().getAuthentication().getName();
        Assertion assertion = getDefaults().assertion(metadata, local, authenticationRequest, principal, NameId.PERSISTENT);

        Response response = getDefaults().response(authenticationRequest,
                                                   assertion,
                                                   metadata,
                                                   local
        );

        String encoded = transformer.samlEncode(transformer.toXml(response), false);
        String destination = authenticationRequest.getAssertionConsumerService().getLocation();
        model.addAttribute("url", destination);
        model.addAttribute("SAMLResponse", encoded);
        return "saml-post";
    }

    protected String getAcs(ServiceProviderMetadata metadata) {
        List<Endpoint> acs = metadata.getServiceProvider().getAssertionConsumerService();
        return acs.get(0).getLocation();
    }


    protected IdentityProviderMetadata getIdentityProviderMetadata(HttpServletRequest request) {
        String base = network.getBasePath(request);
        return getMetadataResolver().getLocalIdentityProvider(base);
    }

    protected String getIdpInitUrl(HttpServletRequest request, ExternalProviderConfiguration p) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(network.getBasePath(request));
        builder.pathSegment("saml/idp/init");
        ServiceProviderMetadata metadata = resolver.resolveServiceProvider(p);
        builder.queryParam("sp", metadata.getEntityId());
        return builder.build().toUriString();
    }

    public SamlTransformer getTransformer() {
        return transformer;
    }

    public Defaults getDefaults() {
        return defaults;
    }

    public MetadataResolver getMetadataResolver() {
        return resolver;
    }
}
