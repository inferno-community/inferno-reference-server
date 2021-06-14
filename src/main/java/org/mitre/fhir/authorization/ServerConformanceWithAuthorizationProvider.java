package org.mitre.fhir.authorization;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.jpa.api.config.DaoConfig;
import ca.uhn.fhir.jpa.api.dao.IFhirSystemDao;
import ca.uhn.fhir.jpa.provider.JpaCapabilityStatementProvider;
import ca.uhn.fhir.parser.IParser;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.RestfulServer;
import ca.uhn.fhir.rest.server.util.ISearchParamRegistry;
import java.io.IOException;
import java.io.InputStream;
import javax.servlet.http.HttpServletRequest;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.CapabilityStatement;
import org.hl7.fhir.r4.model.Meta;
import org.mitre.fhir.utils.FhirReferenceServerUtils;

public class ServerConformanceWithAuthorizationProvider extends JpaCapabilityStatementProvider {

  public static final String TOKEN_EXTENSION_URL = "token";
  public static final String AUTHORIZE_EXTENSION_URL = "authorize";
  public static final String REVOKE_EXTENSION_URL = "revoke";
  private static final String TOKEN_EXTENSION_VALUE_URI = "/oauth/token";
  private static final String AUTHORIZE_EXTENSION_VALUE_URI = "/oauth/authorization";
  private static final String REVOKE_EXTENSION_VALUE_URI = "/oauth/token/revoke-token";

  private static final String CAPABILITY_STATEMENT_FILE_PATH = "capability-statement-template.json";

  private CapabilityStatement capabilityStatement;

  public ServerConformanceWithAuthorizationProvider(RestfulServer theRestfulServer,
      IFhirSystemDao<Bundle, Meta> theSystemDao, DaoConfig theDaoConfig,
      ISearchParamRegistry searchParamRegistry) {
    super(theRestfulServer, theSystemDao, theDaoConfig, searchParamRegistry, null);
  }

  public static String getTokenExtensionUri(HttpServletRequest theRequest) {
    return FhirReferenceServerUtils.getServerBaseUrl(theRequest) + TOKEN_EXTENSION_VALUE_URI;
  }

  public static String getAuthorizationExtensionUri(HttpServletRequest theRequest) {
    return FhirReferenceServerUtils.getServerBaseUrl(theRequest) + AUTHORIZE_EXTENSION_VALUE_URI;
  }

  public static String getRevokeExtensionUri(HttpServletRequest theRequest) {
    return FhirReferenceServerUtils.getServerBaseUrl(theRequest) + REVOKE_EXTENSION_VALUE_URI;
  }

  @Override
  public CapabilityStatement getServerConformance(HttpServletRequest theRequest,
      RequestDetails theRequestDetails) {

    if (capabilityStatement != null) {
      return capabilityStatement;
    }

    FhirContext context = FhirContext.forR4();
    IParser parser = context.newJsonParser();

    String jsonString = getCapabilityStatementJsonString(theRequest);

    capabilityStatement = parser.parseResource(CapabilityStatement.class, jsonString);

    return capabilityStatement;
  }

  private String getCapabilityStatementJsonString(HttpServletRequest theRequest) {
    // read from file
    try {

      InputStream in =
          getClass().getClassLoader().getResourceAsStream(CAPABILITY_STATEMENT_FILE_PATH);
      String capabilityStatementString = new String(in.readAllBytes());

      capabilityStatementString = capabilityStatementString.replaceAll("\\$HOST",
          FhirReferenceServerUtils.getServerBaseUrl(theRequest));

      return capabilityStatementString;

    } catch (IOException e) {
      throw new RuntimeException("Error reading capablity statement");
    }
  }

}
