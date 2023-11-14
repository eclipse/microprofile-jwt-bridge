/*
 * Copyright (c) 2016-2020 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.eclipse.microprofile.jwt.bridge.tck.container.jaxrs;

import static jakarta.ws.rs.core.MediaType.TEXT_PLAIN;
import static org.eclipse.microprofile.jwt.bridge.tck.TCKConstants.TEST_GROUP_EE_SECURITY;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import org.eclipse.microprofile.jwt.bridge.tck.util.MpJwtTestVersion;
import org.eclipse.microprofile.jwt.bridge.tck.util.TokenUtils;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

/**
 * Tests of the MP-JWT auth method authorization behavior as expected by the MP-JWT RBAC 1.0 spec
 */
public class RolesAllowedTest extends Arquillian {

    /**
     * The test generated JWT token string
     */
    private static String token;

    /**
     * The base URL for the container under test
     */
    @ArquillianResource
    private URL baseURL;

    /**
     * Create a CDI aware base web application archive
     *
     * @return the base base web application archive
     * @throws IOException
     *             - on resource failure
     */
    @Deployment(testable = true)
    public static WebArchive createDeployment() throws IOException {
        URL config = RolesAllowedTest.class.getResource("/META-INF/microprofile-config-publickey-location.properties");
        URL publicKey = RolesAllowedTest.class.getResource("/publicKey.pem");
        WebArchive webArchive = ShrinkWrap
                .create(WebArchive.class, "RolesAllowedTest.war")
                .addAsManifestResource(new StringAsset(MpJwtTestVersion.MPJWT_V_1_0.name()),
                        MpJwtTestVersion.MANIFEST_NAME)
                .addAsResource(publicKey, "/publicKey.pem")
                .addClass(RolesEndpoint.class)
                .addClass(TCKApplication.class)
                .addAsWebInfResource("beans.xml", "beans.xml")
                .addAsManifestResource(config, "microprofile-config.properties");
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @BeforeClass(alwaysRun = true)
    public static void generateToken() throws Exception {
        token = TokenUtils.generateTokenString("/Token1.json");
    }

    /**
     * This test requires that the server provide a mapping from the group1 grant in the token to a Group1MappedRole
     * application declared role.
     */
    @RunAsClient
    @Test(groups = TEST_GROUP_EE_SECURITY, description = "Validate a request without an MP-JWT to endpoint requiring role mapping has HTTP_OK")
    public void testNeedsGroup1Mapping() {
        Reporter.log("testNeedsGroup1Mapping, expect HTTP_OK");
        String uri = baseURL.toExternalForm() + "endp/needsGroup1Mapping";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response =
                echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        System.out.println(reply);
    }

}
