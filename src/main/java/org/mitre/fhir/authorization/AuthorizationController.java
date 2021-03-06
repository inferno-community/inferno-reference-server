
package org.mitre.fhir.authorization;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.api.CacheControlDirective;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.github.dnault.xmlpatch.internal.Log;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Bundle.BundleEntryComponent;
import org.hl7.fhir.r4.model.Encounter;
import org.json.JSONObject;
import org.mitre.fhir.HapiReferenceServerProperties;
import org.mitre.fhir.authorization.exception.BearerTokenException;
import org.mitre.fhir.authorization.exception.InvalidBearerTokenException;
import org.mitre.fhir.authorization.exception.InvalidClientIdException;
import org.mitre.fhir.authorization.exception.InvalidClientSecretException;
import org.mitre.fhir.authorization.exception.OpenIdTokenGenerationException;
import org.mitre.fhir.authorization.token.Token;
import org.mitre.fhir.authorization.token.TokenManager;
import org.mitre.fhir.authorization.token.TokenNotFoundException;
import org.mitre.fhir.utils.FhirReferenceServerUtils;
import org.mitre.fhir.utils.FhirUtils;
import org.mitre.fhir.utils.RsaUtils;
import org.mitre.fhir.utils.exception.RsaKeyException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;


@RestController
public class AuthorizationController {

  @PostConstruct
  protected void postConstruct() {
    Log.info("Authorization Controller added");
  }

  /**
   * Get service to validate the client id.
   * 
   * @param clientId client id to be validated
   * @param request the web service request
   * @return
   */
  @GetMapping(path = "authorizeClientId/{clientId}", produces = {"application/json"})
  public String validateClientId(@PathVariable String clientId, HttpServletRequest request) {
    authorizeClientId(clientId);
    String fhirServerBaseUrl = FhirReferenceServerUtils.getServerBaseUrl(request)
        + FhirReferenceServerUtils.FHIR_SERVER_PATH;
    FhirContext fhirContext = FhirContext.forR4();
    IGenericClient client = fhirContext.newRestfulGenericClient(fhirServerBaseUrl);

    Bundle patientsBundle = FhirUtils.getPatientsBundle(client);
    String json = fhirContext.newJsonParser().encodeResourceToString(patientsBundle);

    return json;
  }

  /**
   * Provide a code to get a bearer token for authorization.
   * 
   * @param code code to get token
   * @return bearer token to be used for authorization
   * @throws BearerTokenException error generating a bearer token
   */
  @PostMapping(path = "/token", produces = {"application/json"})
  public ResponseEntity<String> getToken(@RequestParam(name = "code", required = false) String code,
      @RequestParam(name = "client_id", required = false) String clientIdRequestParam,
      @RequestParam(name = "refresh_token", required = false) String refreshTokenValue,
      HttpServletRequest request) throws BearerTokenException {

    Log.info("code is " + code);

    // check client id and client secret if the server is confidential
    String basicHeader = getBasicHeader(request);

    String clientId = null;
    String clientSecret = null;

    // if basic header exists, extract clientId and clientSecret from basic header
    if (basicHeader != null) {
      String decodedValue = getDecodedBasicAuthorizationString(basicHeader);
      String[] splitDecodedValue = decodedValue.split(":");
      // client id is user name, and should be before ':'
      clientId = splitDecodedValue[0];
      // client secret is password, and should be after ':'

      clientSecret = splitDecodedValue.length >= 2 ? splitDecodedValue[1] : "";
    } else {
      // if no basic auth, client id should be supplied as request param
      clientId = clientIdRequestParam;
    }

    authenticateClientIdAndClientSecret(clientId, clientSecret);

    String scopes = "";
    String patientId = "";

    String fullCodeString;

    if (code != null) {
      fullCodeString = code;
      // the provided code is in the format <ACTUAL_CODE>.<SCOPES>
      String[] fullCode = fullCodeString.split("\\.");

      String actualCodeOrRefreshToken = fullCode[0];

      // if scope was included
      if (fullCode.length >= 2) {
        String encodedScopes = fullCode[1];
        scopes = new String(Base64.getDecoder().decode(encodedScopes));
      }

      if (fullCode.length >= 3) {
        String encodedPatientId = fullCode[2];
        patientId = new String(Base64.getDecoder().decode(encodedPatientId));
      }

      if (FhirReferenceServerUtils.SAMPLE_CODE.equals(actualCodeOrRefreshToken)) {
        return generateBearerTokenResponse(request, clientId, scopes, patientId);
      }

    } else if (refreshTokenValue != null) {

      try {
        if (TokenManager.getInstance().authenticateRefreshToken(refreshTokenValue)) {
          Token refreshToken = TokenManager.getInstance().getRefreshToken(refreshTokenValue);
          patientId = refreshToken.getPatientId();
          String refreshTokenScopes = refreshToken.getScopesString();
          return generateBearerTokenResponse(request, clientId, refreshTokenScopes, patientId);
        }
      } catch (TokenNotFoundException tokenNotFoundException) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
            "Refresh Token " + refreshTokenValue + " was not found");
      } catch (InvalidBearerTokenException invalidBearerTokenException) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
            "Refresh Token " + refreshTokenValue + " was not found");
      }
    }

    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid code");
  }

  private ResponseEntity<String> generateBearerTokenResponse(HttpServletRequest request,
      String clientId, String scopes, String patientId) throws BearerTokenException {
    HttpHeaders headers = new HttpHeaders();
    headers.setCacheControl(CacheControl.noStore());
    headers.setPragma("no-cache");

    String tokenJsonString = generateBearerToken(request, clientId, scopes, patientId);

    ResponseEntity<String> responseEntity =
        new ResponseEntity<String>(tokenJsonString, headers, HttpStatus.OK);

    return responseEntity;
  }

  /**
   * Generates Token in Oauth2 expected format.
   * 
   * @return token JSON String
   * @throws BearerTokenException if token generation runs into an error
   */
  private String generateBearerToken(HttpServletRequest request, String clientId, String scopes,
      String patientId) throws BearerTokenException {

    String fhirServerBaseUrl = FhirReferenceServerUtils.getServerBaseUrl(request)
        + FhirReferenceServerUtils.FHIR_SERVER_PATH;
    FhirContext fhirContext = FhirContext.forR4();
    IGenericClient client = fhirContext.newRestfulGenericClient(fhirServerBaseUrl);

    JSONObject tokenJson = new JSONObject();

    TokenManager tokenManager = TokenManager.getInstance();
    Token token = tokenManager.createToken(scopes);

    String refreshTokenValue = "";
    try {
      Token refreshToken = tokenManager.getCorrespondingRefreshToken(token.getTokenValue());
      refreshToken.setPatientId(patientId);
      refreshTokenValue = refreshToken.getTokenValue();
    } catch (Exception exception) {
      throw new BearerTokenException(exception);
    }

    String accessToken = token.getTokenValue();

    tokenJson.put("access_token", accessToken);
    tokenJson.put("token_type", "bearer");
    tokenJson.put("expires_in", 3600);
    tokenJson.put("refresh_token", refreshTokenValue);
    tokenJson.put("scope", scopes);
    tokenJson.put("smart_style_url", FhirReferenceServerUtils.getSmartStyleUrl(request));
    tokenJson.put("need_patient_banner", false);

    if ("".equals(patientId)) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No patients found");
    }

    List<String> scopesList = FhirReferenceServerUtils.getScopesListByScopeString(scopes);

    if (scopesList.contains("launch") || scopesList.contains("launch/patient")) {
      tokenJson.put("patient", patientId);
    }

    if (scopesList.contains("launch") || scopesList.contains("launch/encounter")) {
      Encounter encounter = getFirstEncounterByPatientId(client, patientId);

      if (encounter == null) {
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No encounters found");
      }

      String encounterId = encounter.getIdElement().getIdPart();
      tokenJson.put("encounter", encounterId);
    }

    try {
      tokenJson.put("id_token", generateSampleOpenIdToken(request, clientId, patientId));
    } catch (OpenIdTokenGenerationException openIdTokenGenerationException) {
      throw new BearerTokenException(openIdTokenGenerationException);
    }
    return tokenJson.toString();
  }

  /**
   * Generates a sample open id token https://openid.net/specs/openid-connect-core-1_0.html
   * 
   * @return token JSON String representing the open id token
   * @throws OpenIdTokenGenerationException if error generating open id token
   */
  private String generateSampleOpenIdToken(HttpServletRequest request, String clientId,
      String patientId) throws OpenIdTokenGenerationException {

    try {
      RSAPublicKey publicKey = RsaUtils.getRsaPublicKey();
      RSAPrivateKey privateKey = RsaUtils.getRsaPrivateKey();

      // for now hard coding as a Patient
      // http://hl7.org/fhir/smart-app-launch/worked_example_id_token/index.html#Encode-them-in-a-JWT
      String fhirUserUrl =
          FhirReferenceServerUtils.getFhirServerBaseUrl(request) + "/Patient/" + patientId;

      Calendar calendar = Calendar.getInstance();

      Date issuedAt = calendar.getTime();
      calendar.set(Calendar.YEAR, calendar.get(Calendar.YEAR) + 1);
      Date expiresAt = calendar.getTime();

      Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
      String token = JWT.create().withIssuer(FhirReferenceServerUtils.getFhirServerBaseUrl(request))
          .withSubject("").withAudience(clientId).withExpiresAt(expiresAt).withIssuedAt(issuedAt)
          .withClaim("fhirUser", fhirUserUrl).sign(algorithm);

      return token;
    } catch (RsaKeyException rsaKeyException) {
      throw new OpenIdTokenGenerationException(rsaKeyException);
    }
  }

  private Encounter getFirstEncounterByPatientId(IGenericClient client, String patientId) {
    Encounter encounter = null;

    Token token = TokenManager.getInstance().getServerToken();

    Bundle encountersBundle =
        client.search().forResource(Encounter.class).where(Encounter.PATIENT.hasId(patientId))
            .returnBundle(Bundle.class).cacheControl(new CacheControlDirective().setNoCache(true))
            .withAdditionalHeader(FhirReferenceServerUtils.AUTHORIZATION_HEADER_NAME,
                FhirReferenceServerUtils.createAuthorizationHeaderValue(token.getTokenValue()))
            .execute();
    List<BundleEntryComponent> encounters = encountersBundle.getEntry();

    for (BundleEntryComponent bundleEntryComponent : encounters) {
      if (bundleEntryComponent.getResource().fhirType().equals("Encounter")) {
        encounter = (Encounter) bundleEntryComponent.getResource();
        break;
      }
    }

    return encounter;
  }

  private static String getBasicHeader(HttpServletRequest request) {
    Enumeration<String> authorizationHeaders = request.getHeaders("Authorization");
    // find Basic Auth
    String basicHeader = null;
    while (authorizationHeaders.hasMoreElements()) {
      String header = authorizationHeaders.nextElement();
      if (header.startsWith("Basic ")) {
        basicHeader = header;
        break;
      }
    }

    return basicHeader;
  }

  private static String getDecodedBasicAuthorizationString(String basicHeader) {
    String encodedValue = basicHeader.replaceFirst("Basic ", ""); // strip off the beginning
    Decoder decoder = Base64.getUrlDecoder();
    String decodedValue = new String(decoder.decode(encodedValue));
    return decodedValue;
  }

  private static void authorizeClientId(String clientId) {
    HapiReferenceServerProperties properties = new HapiReferenceServerProperties();
    if (!properties.getPublicClientId().equals(clientId)
        && !properties.getConfidentialClientId().equals(clientId)) {
      throw new InvalidClientIdException(clientId);
    }
  }

  private static void authenticateClientIdAndClientSecret(String clientId, String clientSecret) {

    HapiReferenceServerProperties properties = new HapiReferenceServerProperties();

    authorizeClientId(clientId);

    if (properties.getConfidentialClientId().equals(clientId)
        && !properties.getConfidentialClientSecret().equals(clientSecret)) {
      throw new InvalidClientSecretException();
    }
  }

}
