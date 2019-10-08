package org.mitre.fhir.authorization;

import java.util.List;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;

import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Bundle.BundleEntryComponent;
import org.hl7.fhir.r4.model.Patient;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import com.github.dnault.xmlpatch.internal.Log;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.client.api.IGenericClient;

@RestController
public class AuthorizationController {

	private static final String SAMPLE_CODE = "SAMPLE_CODE";
	private static final String SAMPLE_ACCESS_TOKEN = "SAMPLE_ACCESS_TOKEN";
	private static final String SAMPLE_SCOPE = "launch launch/patient offline_access openid profile user/*.* patient/*.* fhirUser";
	private static final String SAMPLE_REFRESH_TOKEN = "SAMPLE_REFRESH_TOKEN";
	
	public static final String AUTHORIZATION_HEADER_NAME = "Authorization";
	public static final String AUTHORIZATION_HEADER_VALUE = "Bearer SAMPLE_ACCESS_TOKEN";
	public static final String FHIR_SERVER_PATH = "/mitre-fhir/r4";


	@PostConstruct
	protected void postConstruct() {
		Log.info("Authorization Controller added");
	}

	/**
	 * Provide a code to get a bearer token for authorization 
	 * 
	 * @param code
	 * @return bearer token to be used for authorization
	 */
	@PostMapping("/token")
	public ResponseEntity<String> getToken(@RequestParam(name = "code", required = false) String code, HttpServletRequest request) {

		Log.info("code is " + code);

		if (SAMPLE_CODE.equals(code)) {
			return generateBearerTokenResponse(request);
		}

		throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid code");
	}
	
	private ResponseEntity<String> generateBearerTokenResponse(HttpServletRequest request) {
		HttpHeaders headers = new HttpHeaders();
		headers.setCacheControl(CacheControl.noStore());
		headers.setPragma("no-cache");

		String tokenJSONString = generateBearerToken(request);
		ResponseEntity<String> responseEntity = new ResponseEntity<String>(tokenJSONString, headers, HttpStatus.OK);

		return responseEntity;
	}

	/**
	 * Generates Token in Oauth2 expected format
	 * 
	 * @return token JSON String
	 */
	private String generateBearerToken(HttpServletRequest request) {
				
		String serverBaseUrl = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + FHIR_SERVER_PATH;
				
		FhirContext fhirContext = FhirContext.forR4();
		IGenericClient client = fhirContext.newRestfulGenericClient(serverBaseUrl);

		//get the first patient in the db
        Bundle patientsBundle =   client.search().forResource(Patient.class).returnBundle(Bundle.class).withAdditionalHeader(AUTHORIZATION_HEADER_NAME, AUTHORIZATION_HEADER_VALUE).execute();
        List<BundleEntryComponent> patients = patientsBundle.getEntry();        
        Patient patient = null;
        for (BundleEntryComponent bundleEntryComponent : patients)
        {
        	System.out.println("FhirType " + bundleEntryComponent.getResource().fhirType());
        	if (bundleEntryComponent.getResource().fhirType().equals("Patient"))
        	{
        		patient = (Patient)bundleEntryComponent.getResource();
        		break;
        	}
        }
        
        if (patient == null)
        {
        	throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No patients found");
        }
        
        //get their id
    	String patientId = patient.getIdElement().getIdPart();
 
		String tokenString = "{" 
				+ "\"access_token\":\"" + SAMPLE_ACCESS_TOKEN + "\"," 
				+ "\"token_type\":\"bearer\","
				+ "\"expires_in\":3600," 
				+ "\"refresh_token\":\"" + SAMPLE_REFRESH_TOKEN + "\","
				+ "\"scope\":\"" + SAMPLE_SCOPE + "\"," 
				+ "\"patient\": " + patientId 
			+ "}";

		return tokenString;
	}
}
