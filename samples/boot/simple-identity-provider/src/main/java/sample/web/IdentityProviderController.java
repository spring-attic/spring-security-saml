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

import org.springframework.http.MediaType;
import org.springframework.security.saml.init.Defaults;
import org.springframework.security.saml.init.SpringSecuritySaml;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IdentityProviderController {

    @GetMapping(value = "/saml/idp/metadata", produces = MediaType.TEXT_XML_VALUE)
    public @ResponseBody()
    String metadata(HttpServletRequest request) {
        String base = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
        IdentityProviderMetadata metadata = Defaults.identityProviderMetadata(base, null, null);
        return SpringSecuritySaml.getInstance().toXml(metadata);
    }

    @RequestMapping("/saml/sp/SSO")
    public String sso(HttpServletRequest request) {
        //receive AuthnRequest
        return null;
    }
}
