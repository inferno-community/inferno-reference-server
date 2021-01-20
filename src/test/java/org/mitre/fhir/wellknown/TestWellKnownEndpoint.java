package org.mitre.fhir.wellknown;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;
import org.mitre.fhir.utils.RsaUtils;
import org.mitre.fhir.utils.exception.RsaKeyException;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Base64.Decoder;

public class TestWellKnownEndpoint {

  @Test
  public void testWellKnownEndpoint() throws IOException {
    WellKnownAuthorizationEndpointController wellKnownEndpoint = new WellKnownAuthorizationEndpointController();
    MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();

    mockHttpServletRequest.setScheme("http");
    mockHttpServletRequest.setServerName("www.example.org");
    mockHttpServletRequest.setServerPort(123);
    mockHttpServletRequest.setRequestURI("/.well-known/smart-configuration");

    String jSONString = wellKnownEndpoint.getWellKnownJson(mockHttpServletRequest);

    ObjectMapper mapper = new ObjectMapper();
    JsonNode jsonNode = mapper.readTree(jSONString);

    String authorizationEndpoint = jsonNode.get("authorization_endpoint").asText();
    Assert.assertEquals("http://www.example.org:123/reference-server/oauth/authorization", authorizationEndpoint);


    String tokenEndpoint = jsonNode.get("token_endpoint").asText();
    Assert.assertEquals("http://www.example.org:123/reference-server/oauth/token", tokenEndpoint);
  }

  @Test
  public void testGetJWKModulusAndExponent() throws IllegalArgumentException, RsaKeyException {
    WellKnownAuthorizationEndpointController wellKnownEndpoint = new WellKnownAuthorizationEndpointController();
    MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();

    mockHttpServletRequest.setScheme("http");
    mockHttpServletRequest.setServerName("www.example.org");
    mockHttpServletRequest.setServerPort(123);
    mockHttpServletRequest.setRequestURI("/.well-known/smart-configuration");

    String jSONString = wellKnownEndpoint.getJwk(mockHttpServletRequest);
    JSONObject jsonObject = new JSONObject(jSONString);
    JSONArray keys = (JSONArray) jsonObject.get("keys");
    JSONObject firstKey = ((JSONObject) (keys.get(0)));
    String modulusString = (String) firstKey.get("n");
    String exponentString = (String) firstKey.get("e");
    Decoder decoder = Base64.getUrlDecoder();
    BigInteger modulus = new BigInteger(decoder.decode(modulusString));
    BigInteger exponent = new BigInteger(decoder.decode(exponentString));

    //sign a jwt with the rsa public key
    Algorithm algorithm = Algorithm.RSA256(RsaUtils.getRsaPublicKey(), RsaUtils.getRsaPrivateKey());
    String token = JWT.create().withIssuer("issuer").sign(algorithm);

    RSAPublicKey publicKeyFromJWK = new RSAPublicKey() {

      private static final long serialVersionUID = 1L;

      @Override
      public String getAlgorithm() {
        return "RSA";
      }

      @Override
      public String getFormat() {
        // TODO Auto-generated method stub
        return null;
      }

      @Override
      public byte[] getEncoded() {
        // TODO Auto-generated method stub
        return null;
      }

      @Override
      public BigInteger getModulus() {

        return modulus;
      }

      @Override
      public BigInteger getPublicExponent() {
        return exponent;
      }

    };

    Algorithm algorithm2 = Algorithm.RSA256(publicKeyFromJWK, null);

    //will throw an exception if wrong key
    JWT.require(algorithm2).build().verify(token);


  }
}
