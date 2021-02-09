package org.mitre.fhir.authorization;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import ca.uhn.fhir.rest.client.api.ServerValidationModeEnum;
import ca.uhn.fhir.rest.client.interceptor.LoggingInterceptor;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.stefanbirkner.systemlambda.SystemLambda;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.webapp.WebAppContext;
import org.hl7.fhir.instance.model.api.IIdType;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Bundle.BundleEntryComponent;
import org.hl7.fhir.r4.model.CapabilityStatement;
import org.hl7.fhir.r4.model.CapabilityStatement.CapabilityStatementRestComponent;
import org.hl7.fhir.r4.model.CapabilityStatement.CapabilityStatementRestSecurityComponent;
import org.hl7.fhir.r4.model.Encounter;
import org.hl7.fhir.r4.model.Extension;
import org.hl7.fhir.r4.model.Patient;
import org.hl7.fhir.r4.model.Reference;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mitre.fhir.authorization.exception.BearerTokenException;
import org.mitre.fhir.authorization.exception.InvalidClientIdException;
import org.mitre.fhir.authorization.exception.InvalidClientSecretException;
import org.mitre.fhir.authorization.token.Token;
import org.mitre.fhir.authorization.token.TokenManager;
import org.mitre.fhir.authorization.token.TokenNotFoundException;
import org.mitre.fhir.utils.FhirReferenceServerUtils;
import org.mitre.fhir.utils.FhirUtils;
import org.mitre.fhir.utils.RsaUtils;
import org.mitre.fhir.utils.TestUtils;
import org.mitre.fhir.utils.exception.RsaKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.server.ResponseStatusException;

public class TestAuthorization {

  private static IGenericClient ourClient;
  private static FhirContext ourCtx;
  private static int ourPort;
  private static Server ourServer;
  private static String ourServerBase;

  private static IIdType testPatientId;
  private static IIdType testEncounterId;

  private static Token testToken;

  private static final String SAMPLE_CODE = "SAMPLE_CODE";

  private static final String SAMPLE_PUBLIC_CLIENT_ID = "SAMPLE_PUBLIC_CLIENT_ID";
  private static final String SAMPLE_CONFIDENTIAL_CLIENT_ID = "SAMPLE_CONFIDENTIAL_CLIENT_ID";
  private static final String SAMPLE_CONFIDENTIAL_CLIENT_SECRET =
      "SAMPLE_CONFIDENTIAL_CLIENT_SECRET";

  @Test
  public void testCreateAndRead() {

    String methodName = "testCreateResourceConditional";

    Patient pt = new Patient();
    pt.addName().setFamily(methodName);
    IIdType id = ourClient.create().resource(pt)
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(testToken.getTokenValue()))
        .execute().getId();

    Patient pt2 = ourClient.read().resource(Patient.class).withId(id)
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(testToken.getTokenValue()))
        .execute();
    Assert.assertEquals(methodName, pt2.getName().get(0).getFamily());

    // delete the new entry so the db won't have a leftover artifact
    ourClient.delete().resourceById(id)
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(testToken.getTokenValue()))
        .execute();

  }

  @Test(expected = AuthenticationException.class)
  public void testInterceptor() {
    String methodName = "testCreateResourceConditional";

    // with no header, will fail
    Patient pt = new Patient();
    pt.addName().setFamily(methodName);

    ourClient.create().resource(pt).execute();
  }

  @Test(expected = AuthenticationException.class)
  public void testInterceptorScopes() {

    String scope = "launch/patient patient/Patient.read patient/Condition patient/Observation.read";
    Token token = TokenManager.getInstance().createToken(scope);

    ourClient.search().forResource("Patient")
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(token.getTokenValue()))
        .execute();

    ourClient.search().forResource("Condition")
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(token.getTokenValue()))
        .execute();

    ourClient.search().forResource("Observation")
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(token.getTokenValue()))
        .execute();

    ourClient.search().forResource("AllergyIntolerance")
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(token.getTokenValue()))
        .execute();

  }

  @Test
  public void testInterceptorWithStarScopes() {
    String scope = "patient/*.*";
    Token token = TokenManager.getInstance().createToken(scope);

    ourClient.search().forResource("Patient")
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(token.getTokenValue()))
        .execute();

    ourClient.search().forResource("Condition")
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(token.getTokenValue()))
        .execute();

    ourClient.search().forResource("Observation")
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(token.getTokenValue()))
        .execute();

  }

  @Test
  public void testInterceptorWithSkipTokenAuthenticationEnvironmentVariable() throws Exception {

    SystemLambda.withEnvironmentVariable("SKIP_TOKEN_AUTHENTICATION", "true")
        .execute(() -> ourClient.search().forResource("Patient").execute());
  }

  @Test(expected = AuthenticationException.class)
  public void testIntercepterWithoutToken() {
    ourClient.search().forResource("Patient").execute();
  }

  @Test
  public void testTestAuthorizationWithInvalidCode()
      throws JSONException, BearerTokenException, TokenNotFoundException {
    AuthorizationController authorizationController = new AuthorizationController();

    try {
      String serverBaseUrl = "";
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.setLocalAddr("localhost");
      request.setRequestURI(serverBaseUrl);
      request.setServerPort(TestUtils.TEST_PORT);

      authorizationController.getToken("INVALID_CODE", null, null, request);
      Assert.fail("Did not get expected Unauthorized ResponseStatusException");
    } catch (ResponseStatusException rse) {
      if (!HttpStatus.UNAUTHORIZED.equals(rse.getStatus())) {
        throw rse;
      }
    }
  }

  @Test
  public void testTestAuthorizationWithNullCode()
      throws JSONException, BearerTokenException, TokenNotFoundException {
    AuthorizationController authorizationController = new AuthorizationController();

    try {
      String serverBaseUrl = "";
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.setLocalAddr("localhost");
      request.setRequestURI(serverBaseUrl);
      request.setServerPort(TestUtils.TEST_PORT);

      authorizationController.getToken(null, null, "SAMPLE_CLIENT_ID", request);
      Assert.fail("Did not get expected Unauthorized ResponseStatusException");
    } catch (ResponseStatusException rse) {
      if (!HttpStatus.UNAUTHORIZED.equals(rse.getStatus())) {
        throw rse;
      }
    }
  }
  
  @Test
  public void testTestAuthorizationWithPublicClient() throws IOException, JSONException,
      BearerTokenException, TokenNotFoundException, TokenNotFoundException {
    AuthorizationController authorizationController = new AuthorizationController();
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);
    request.addHeader("Authorization", TestUtils.getEncodedBasicAuthorizationHeaderWithPublicClient());

    String scopes = "launch/patient openId ";
    String code =
        FhirReferenceServerUtils.createCode(SAMPLE_CODE, scopes, testPatientId.getIdPart());

    ResponseEntity<String> tokenResponseEntity =
        authorizationController.getToken(code, "SAMPLE_PUBLIC_CLIENT_ID", null, request);

    ObjectMapper mapper = new ObjectMapper();

    String jsonString = tokenResponseEntity.getBody();

    JsonNode jsonNode = mapper.readTree(jsonString);
    Assert.assertNotNull(jsonNode.get("access_token"));

  }

  @Test
  public void testTestAuthorizationWithValidCode() throws IOException, JSONException,
      BearerTokenException, TokenNotFoundException, TokenNotFoundException {
    AuthorizationController authorizationController = new AuthorizationController();
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);
    request.addHeader("Authorization", TestUtils.getEncodedBasicAuthorizationHeader());

    String scopes = "launch/patient openId ";
    String code =
        FhirReferenceServerUtils.createCode(SAMPLE_CODE, scopes, testPatientId.getIdPart());

    ResponseEntity<String> tokenResponseEntity =
        authorizationController.getToken(code, "SAMPLE_PUBLIC_CLIENT_ID", null, request);

    ObjectMapper mapper = new ObjectMapper();

    String jsonString = tokenResponseEntity.getBody();

    JsonNode jsonNode = mapper.readTree(jsonString);
    Assert.assertNotNull(jsonNode.get("access_token"));

  }

  @Test
  public void testReadScopeNoScopeProvided()
      throws IOException, JSONException, BearerTokenException, TokenNotFoundException {
    AuthorizationController authorizationController = new AuthorizationController();
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);

    String scopes = "";
    ResponseEntity<String> tokenResponseEntity = authorizationController.getToken(
        FhirReferenceServerUtils.createCode(SAMPLE_CODE, scopes, testPatientId.getIdPart()),
        "SAMPLE_PUBLIC_CLIENT_ID", null, request);

    ObjectMapper mapper = new ObjectMapper();

    String jsonString = tokenResponseEntity.getBody();

    JsonNode jsonNode = mapper.readTree(jsonString);
    String scope = jsonNode.get("scope").asText();

    Assert.assertEquals("", scope);
  }

  @Test
  public void testReadScope()
      throws IOException, JSONException, BearerTokenException, TokenNotFoundException {
    AuthorizationController authorizationController = new AuthorizationController();
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);

    String scopes = "/patient openId _-\\/";

    ResponseEntity<String> tokenResponseEntity = authorizationController.getToken(
        FhirReferenceServerUtils.createCode(SAMPLE_CODE, scopes, testPatientId.getIdPart()),
        "SAMPLE_PUBLIC_CLIENT_ID", null, request);

    ObjectMapper mapper = new ObjectMapper();

    String jsonString = tokenResponseEntity.getBody();

    JsonNode jsonNode = mapper.readTree(jsonString);
    String scopeResult = jsonNode.get("scope").asText();

    Assert.assertEquals(scopes, scopeResult);
  }

  @Test
  public void testCapabilityStatementNotBlockedByInterceptor() {
    // should throw an exception if intercepter does not white list it
    ourClient.capabilities().ofType(CapabilityStatement.class).execute();
  }

  @Test
  public void testCapabilityStatementListResourceIsCorrect() {
    // Get the CapabilityStatement
    CapabilityStatement capabilityStatement =
        ourClient.capabilities().ofType(CapabilityStatement.class).execute();
    capabilityStatement.getRest().get(0).getResource().stream()
        .filter(restResource -> "List".equals(restResource.getType())).findFirst()
        .ifPresent(listResource -> Assert.assertEquals(listResource.getProfile(),
            "http://hl7.org/fhir/StructureDefinition/List"));
  }

  @Test
  public void testCapabilityStatementOauthUris() {
    CapabilityStatement capabilityStatement =
        ourClient.capabilities().ofType(CapabilityStatement.class).execute();
    CapabilityStatementRestComponent rest = capabilityStatement.getRest().get(0);
    CapabilityStatementRestSecurityComponent security = rest.getSecurity();
    List<Extension> extensions = security.getExtension();

    Extension oauthUrisExtension = extensions.get(0);

    List<Extension> oauthUrisExtensionExtensions = oauthUrisExtension.getExtension();

    Map<String, String> oauthUriMap = new HashMap<>();
    for (Extension extension : oauthUrisExtensionExtensions) {
      oauthUriMap.put(extension.getUrl(), extension.getValue().primitiveValue());
    }

    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);

    String authorizeUri =
        oauthUriMap.get(ServerConformanceWithAuthorizationProvider.AUTHORIZE_EXTENSION_URL);
    String revokeUri =
        oauthUriMap.get(ServerConformanceWithAuthorizationProvider.REVOKE_EXTENSION_URL);
    String tokenUri =
        oauthUriMap.get(ServerConformanceWithAuthorizationProvider.TOKEN_EXTENSION_URL);

    Assert.assertEquals(authorizeUri,
        ServerConformanceWithAuthorizationProvider.getAuthorizationExtensionUri(request));
    Assert.assertEquals(revokeUri,
        ServerConformanceWithAuthorizationProvider.getRevokeExtensionUri(request));
    Assert.assertEquals(tokenUri,
        ServerConformanceWithAuthorizationProvider.getTokenExtensionUri(request));

  }


  @Test
  public void testGetTokenWithoutBasicAuth()
      throws JSONException, BearerTokenException, TokenNotFoundException {
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);

    String scopes = "";
    AuthorizationController authorizationController = new AuthorizationController();
    // shouldn't throw an exception
    authorizationController.getToken(
        FhirReferenceServerUtils.createCode(SAMPLE_CODE, scopes, testPatientId.getIdPart()),
        SAMPLE_PUBLIC_CLIENT_ID, null, request);
  }

  @Test(expected = InvalidClientIdException.class)
  public void testGetTokenWithoutBasicAuthAndInvalidClientId()
      throws JSONException, BearerTokenException, TokenNotFoundException {
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);
    AuthorizationController authorizationController = new AuthorizationController();
    authorizationController.getToken(FhirReferenceServerUtils.SAMPLE_CODE, "INVALID_CLIENT_ID",
        null, request);
  }

  @Test(expected = InvalidClientIdException.class)
  public void testGetTokenWithoutBasicAuthAndNullClientId()
      throws JSONException, BearerTokenException, TokenNotFoundException {
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);

    AuthorizationController authorizationController = new AuthorizationController();
    authorizationController.getToken(FhirReferenceServerUtils.SAMPLE_CODE, null, null, request);
  }

  @Test
  public void testGetTokenWithBasicAuth()
      throws JSONException, BearerTokenException, TokenNotFoundException {
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);
    request.addHeader("Authorization", TestUtils.getEncodedBasicAuthorizationHeader());

    AuthorizationController authorizationController = new AuthorizationController();
    authorizationController.getToken(
        FhirReferenceServerUtils.createCode(SAMPLE_CODE, "", testPatientId.getIdPart()), null, null,
        request);
  }

  @Test(expected = ResponseStatusException.class)
  public void testGetTokenNoPatientScopeProvided()
      throws JSONException, BearerTokenException, TokenNotFoundException {
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);
    request.addHeader("Authorization", TestUtils.getEncodedBasicAuthorizationHeader());

    AuthorizationController authorizationController = new AuthorizationController();
    authorizationController.getToken(FhirReferenceServerUtils.SAMPLE_CODE, null, null, request);

  }

  @Test
  public void testGetTokenNoEncounterScopeProvided()
      throws IOException, JSONException, BearerTokenException, TokenNotFoundException {
    AuthorizationController authorizationController = new AuthorizationController();
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);

    String scopes = "launch/patient openId ";

    String code =
        FhirReferenceServerUtils.createCode(SAMPLE_CODE, scopes, testPatientId.getIdPart());

    ResponseEntity<String> tokenResponseEntity =
        authorizationController.getToken(code, "SAMPLE_PUBLIC_CLIENT_ID", null, request);

    ObjectMapper mapper = new ObjectMapper();

    String jsonString = tokenResponseEntity.getBody();

    JsonNode jsonNode = mapper.readTree(jsonString);
    JsonNode patientId = jsonNode.get("patient");
    JsonNode encounterId = jsonNode.get("encounter");

    Assert.assertNotNull(patientId);
    Assert.assertNull(encounterId);
  }

  @Test
  public void testGetTokenNoPatientOrEncounterScopeProvided()
      throws IOException, JSONException, BearerTokenException, TokenNotFoundException {
    AuthorizationController authorizationController = new AuthorizationController();
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);

    String scopes = "";

    String code =
        FhirReferenceServerUtils.createCode(SAMPLE_CODE, scopes, testPatientId.getIdPart());

    ResponseEntity<String> tokenResponseEntity =
        authorizationController.getToken(code, "SAMPLE_PUBLIC_CLIENT_ID", null, request);

    ObjectMapper mapper = new ObjectMapper();

    String jsonString = tokenResponseEntity.getBody();

    JsonNode jsonNode = mapper.readTree(jsonString);
    JsonNode patientId = jsonNode.get("patient");
    JsonNode encounterId = jsonNode.get("encounter");

    Assert.assertNull(patientId);
    Assert.assertNull(encounterId);
  }

  @Test
  public void testPatientAndEncounterScopeProvided()
      throws IOException, JSONException, BearerTokenException, TokenNotFoundException {
    AuthorizationController authorizationController = new AuthorizationController();
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);

    String scopes = "launch/patient launch/encounter ";

    ResponseEntity<String> tokenResponseEntity = authorizationController.getToken(
        FhirReferenceServerUtils.createCode(SAMPLE_CODE, scopes, testPatientId.getIdPart()),
        "SAMPLE_PUBLIC_CLIENT_ID", null, request);

    ObjectMapper mapper = new ObjectMapper();

    String jsonString = tokenResponseEntity.getBody();

    JsonNode jsonNode = mapper.readTree(jsonString);
    String patientId = jsonNode.get("patient").asText();
    String encounterId = jsonNode.get("encounter").asText();

    Assert.assertNotNull(patientId);
    Assert.assertNotNull(encounterId);
  }

  @Test
  public void testNoPatientScopeButEncounterScopeProvided()
      throws IOException, JSONException, BearerTokenException, TokenNotFoundException {
    AuthorizationController authorizationController = new AuthorizationController();
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);

    String scopes = "launch/encounter ";

    ResponseEntity<String> tokenResponseEntity = authorizationController.getToken(
        FhirReferenceServerUtils.createCode(SAMPLE_CODE, scopes, testPatientId.getIdPart()),
        "SAMPLE_PUBLIC_CLIENT_ID", null, request);

    ObjectMapper mapper = new ObjectMapper();

    String jsonString = tokenResponseEntity.getBody();

    JsonNode jsonNode = mapper.readTree(jsonString);
    JsonNode patientId = jsonNode.get("patient");
    JsonNode encounterId = jsonNode.get("encounter");

    Assert.assertNull(patientId);
    Assert.assertNotNull(encounterId);
  }

  @Test(expected = InvalidClientIdException.class)
  public void testGetTokenWithBasicAuthWithInvalidClientId()
      throws JSONException, BearerTokenException, TokenNotFoundException {
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);
    request.addHeader("Authorization", TestUtils.getEncodedBasicAuthorizationHeader(
        "INVALID_CLIENT_ID", SAMPLE_CONFIDENTIAL_CLIENT_SECRET));
    String encodedScopes = "";
    String code = FhirReferenceServerUtils.SAMPLE_CODE + encodedScopes;

    AuthorizationController authorizationController = new AuthorizationController();
    authorizationController.getToken(code, null, null, request);
  }

  @Test
  public void testGetTokenWithBasicAuthWithConfidentialClientId()
      throws JSONException, BearerTokenException, TokenNotFoundException {
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);
    request.addHeader("Authorization", TestUtils.getEncodedBasicAuthorizationHeader(
        SAMPLE_CONFIDENTIAL_CLIENT_ID, SAMPLE_CONFIDENTIAL_CLIENT_SECRET));
    String scopes = "";

    AuthorizationController authorizationController = new AuthorizationController();
    // no error should be thrown
    authorizationController.getToken(
        FhirReferenceServerUtils.createCode(SAMPLE_CODE, scopes, testPatientId.getIdPart()), null,
        null, request);
  }

  @Test(expected = InvalidClientSecretException.class)
  public void testGetTokenWithBasicAuthWithInvalidClientSecret()
      throws JSONException, BearerTokenException, TokenNotFoundException {
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);
    request.addHeader("Authorization", TestUtils.getEncodedBasicAuthorizationHeader(
        SAMPLE_CONFIDENTIAL_CLIENT_ID, "Invalid Client Secret"));

    AuthorizationController authorizationController = new AuthorizationController();
    authorizationController.getToken(FhirReferenceServerUtils.SAMPLE_CODE, null, null, request);
  }

  @Test
  public void testGetTokenGivesValidOpenId() throws IllegalArgumentException, RsaKeyException,
      JSONException, BearerTokenException, TokenNotFoundException {
    AuthorizationController authorizationController = new AuthorizationController();
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);
    request.addHeader("Authorization", TestUtils.getEncodedBasicAuthorizationHeader());

    String scopes = "";
    ResponseEntity<String> tokenResponseEntity = authorizationController.getToken(
        FhirReferenceServerUtils.createCode(SAMPLE_CODE, scopes, testPatientId.getIdPart()), null,
        null, request);
    String jsonString = tokenResponseEntity.getBody();
    JSONObject jsonObject = new JSONObject(jsonString);
    String idToken = (String) jsonObject.get("id_token");

    // will throw an exception if invalid
    DecodedJWT decoded = JWT.decode(idToken);
    Algorithm algorithm = Algorithm.RSA256(RsaUtils.getRsaPublicKey(), null);

    JWT.require(algorithm).build().verify(decoded);

    Assert.assertEquals("RS256", decoded.getAlgorithm());
    Assert.assertNotNull(decoded.getClaim("fhirUser"));
  }

  @Test
  public void testTestAuthorizationWithRefreshToken() throws IOException, JSONException,
      BearerTokenException, TokenNotFoundException, TokenNotFoundException {
    AuthorizationController authorizationController = new AuthorizationController();
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);
    request.addHeader("Authorization", TestUtils.getEncodedBasicAuthorizationHeader());

    Token token = TokenManager.getInstance().getServerToken();
    Token refreshToken =
        TokenManager.getInstance().getCorrespondingRefreshToken(token.getTokenValue());

    String refreshTokenValue = refreshToken.getTokenValue();

    ResponseEntity<String> tokenResponseEntity = authorizationController.getToken(null,
        "SAMPLE_PUBLIC_CLIENT_ID", refreshTokenValue, request);

    ObjectMapper mapper = new ObjectMapper();

    String jsonString = tokenResponseEntity.getBody();

    JsonNode jsonNode = mapper.readTree(jsonString);
    Assert.assertNotNull(jsonNode.get("access_token"));

  }

  @Test
  public void testUsingRefreshTokenReceivedFromToken()
      throws BearerTokenException, JsonMappingException, JsonProcessingException {
    AuthorizationController authorizationController = new AuthorizationController();
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);
    request.addHeader("Authorization", TestUtils.getEncodedBasicAuthorizationHeader());

    String scopes = "launch/patient openId";
    String patientId = testPatientId.getIdPart();
    String code = FhirReferenceServerUtils.createCode(SAMPLE_CODE, scopes, patientId);

    ResponseEntity<String> tokenResponseEntity =
        authorizationController.getToken(code, "SAMPLE_PUBLIC_CLIENT_ID", null, request);

    ObjectMapper mapper = new ObjectMapper();

    String jsonString = tokenResponseEntity.getBody();

    JsonNode jsonNode = mapper.readTree(jsonString);
    String refreshToken = jsonNode.get("refresh_token").textValue();

    String serverBaseUrl2 = "";
    MockHttpServletRequest request2 = new MockHttpServletRequest();
    request2.setLocalAddr("localhost");
    request2.setRequestURI(serverBaseUrl2);
    request2.setServerPort(TestUtils.TEST_PORT);
    request2.addHeader("Authorization", TestUtils.getEncodedBasicAuthorizationHeader());



    // check that the new token has the same scopes and the new refresh token has the same patient
    // id
    ResponseEntity<String> newTokenResponseEntity =
        authorizationController.getToken(null, "SAMPLE_PUBLIC_CLIENT_ID", refreshToken, request2);
    String newJsonString = newTokenResponseEntity.getBody();
    ObjectMapper mapper2 = new ObjectMapper();
    JsonNode newJsonNode = mapper2.readTree(newJsonString);
    String newScopes = newJsonNode.get("scope").textValue();

    Assert.assertEquals(newScopes, scopes);

    String newPatientId = newJsonNode.get("patient").textValue();

    Assert.assertEquals(newPatientId, patientId);



  }

  @Test(expected = ResponseStatusException.class)
  public void testTestAuthorizationNoCodeAndNoRefreshToken()
      throws IOException, JSONException, BearerTokenException, TokenNotFoundException {
    AuthorizationController authorizationController = new AuthorizationController();
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);
    request.addHeader("Authorization", TestUtils.getEncodedBasicAuthorizationHeader());

    ResponseEntity<String> tokenResponseEntity =
        authorizationController.getToken(null, "SAMPLE_PUBLIC_CLIENT_ID", null, request);

    ObjectMapper mapper = new ObjectMapper();

    String jsonString = tokenResponseEntity.getBody();

    JsonNode jsonNode = mapper.readTree(jsonString);
    String accessToken = jsonNode.get("access_token").asText();

    Assert.assertEquals("SAMPLE_ACCESS_TOKEN", accessToken);
  }

  @Test(expected = ResponseStatusException.class)
  public void testTestAuthorizationInvalidRefreshToken()
      throws IOException, JSONException, BearerTokenException, TokenNotFoundException {
    AuthorizationController authorizationController = new AuthorizationController();
    String serverBaseUrl = "";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setLocalAddr("localhost");
    request.setRequestURI(serverBaseUrl);
    request.setServerPort(TestUtils.TEST_PORT);
    request.addHeader("Authorization", TestUtils.getEncodedBasicAuthorizationHeader());

    String scopes = "launch/patient openId ";
    String refreshToken = FhirReferenceServerUtils.createCode("INCORRECT_REFRESH_TOKEN", scopes,
        testPatientId.getIdPart());

    ResponseEntity<String> tokenResponseEntity =
        authorizationController.getToken(null, "SAMPLE_PUBLIC_CLIENT_ID", refreshToken, request);

    ObjectMapper mapper = new ObjectMapper();

    String jsonString = tokenResponseEntity.getBody();

    JsonNode jsonNode = mapper.readTree(jsonString);
    String accessToken = jsonNode.get("access_token").asText();

    Assert.assertEquals("SAMPLE_ACCESS_TOKEN", accessToken);
  }
  
  @Test
  public void myTest()
  {
    Token token = TokenManager.getInstance().getServerToken();

    Bundle bundle = ourClient.search().forResource("Patient").returnBundle(Bundle.class).count(1000)
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(token.getTokenValue()))
        .execute();
  }

  @Test
  public void testGetAllPatientsBundle() {
    Bundle bundle = FhirUtils.getPatientsBundle(ourClient);
    List<BundleEntryComponent> bundleEntryComponents = bundle.getEntry();

    Assert.assertEquals(1, bundleEntryComponents.size());
  }

  @AfterClass
  public static void afterClass() throws Exception {

    // delete test patient and encounter

    ourClient.delete().resourceById(testEncounterId)
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(testToken.getTokenValue()))
        .execute();

    ourClient.delete().resourceById(testPatientId)
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(testToken.getTokenValue()))
        .execute();

    testPatientId = null;
    testEncounterId = null;

    // clear db just in case there are any erroneous patients or encounters
    TestUtils.clearDB(ourClient);

    ourServer.stop();
  }

  @BeforeClass
  public static void beforeClass() throws Exception {


    testToken = TokenManager.getInstance().getServerToken();

    ourCtx = FhirContext.forR4();

    if (ourPort == 0) {
      ourPort = TestUtils.TEST_PORT;
    }
    ourServer = new Server(ourPort);

    String path = Paths.get("").toAbsolutePath().toString();

    WebAppContext webAppContext = new WebAppContext();
    webAppContext.setContextPath("");
    webAppContext.setDisplayName("HAPI FHIR");
    webAppContext.setDescriptor(path + "/src/main/webapp/WEB-INF/web.xml");
    webAppContext.setResourceBase(path + "/target/mitre-fhir-starter");
    webAppContext.setParentLoaderPriority(true);

    ourServer.setHandler(webAppContext);
    ourServer.start();

    ourCtx.getRestfulClientFactory().setServerValidationMode(ServerValidationModeEnum.NEVER);
    ourCtx.getRestfulClientFactory().setSocketTimeout(1200 * 1000);
    ourServerBase = "http://localhost:" + ourPort + "/reference-server/r4/";

    ourClient = ourCtx.newRestfulGenericClient(ourServerBase);
    ourClient.registerInterceptor(new LoggingInterceptor(true));
    ourClient.capabilities();

    // ensure that db is not empty (will be deleted @AfterClass)
    Patient pt = new Patient();
    pt.addName().setFamily("Test");
    testPatientId = ourClient.create().resource(pt)
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(testToken.getTokenValue()))
        .execute().getId();

    Encounter encounter = new Encounter();
    encounter.setSubject(new Reference().setReference("Patient/" + testPatientId.getIdPart()));
    testEncounterId = ourClient.create().resource(encounter)
        .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
            FhirReferenceServerUtils.createAuthorizationHeaderValue(testToken.getTokenValue()))
        .execute().getId();

  }

}
