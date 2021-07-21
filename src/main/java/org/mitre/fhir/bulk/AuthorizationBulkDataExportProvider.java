package org.mitre.fhir.bulk;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.jpa.bulk.export.api.IBulkDataExportSvc;
import ca.uhn.fhir.jpa.bulk.export.model.BulkExportResponseJson;
import ca.uhn.fhir.jpa.bulk.export.provider.BulkDataExportProvider;
import ca.uhn.fhir.jpa.model.util.JpaConstants;
import ca.uhn.fhir.rest.annotation.IdParam;
import ca.uhn.fhir.rest.annotation.Operation;
import ca.uhn.fhir.rest.annotation.OperationParam;
import ca.uhn.fhir.rest.api.Constants;
import ca.uhn.fhir.rest.server.exceptions.InvalidRequestException;
import ca.uhn.fhir.rest.server.servlet.ServletRequestDetails;
import ca.uhn.fhir.util.JsonUtil;
import ca.uhn.fhir.util.OperationOutcomeUtil;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.hl7.fhir.instance.model.api.IBaseOperationOutcome;
import org.hl7.fhir.instance.model.api.IIdType;
import org.hl7.fhir.instance.model.api.IPrimitiveType;
import org.hl7.fhir.r4.model.InstantType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;


/**
 * Bulk Data Export Provider with Required Fhir Authentication. Some of this is copied from
 * BulkDataExportProvider.java to edit it's behavior
 * 
 * @author hershil
 *
 */
public class AuthorizationBulkDataExportProvider extends BulkDataExportProvider {

  private static final String ACCEPT = "accept";

  private static final List<String> VALID_ACCEPT_HEADERS = new ArrayList<String>();

  @Autowired
  private IBulkDataExportSvc myBulkDataExportSvc;
  @Autowired
  private FhirContext myFhirContext;

  static {
    VALID_ACCEPT_HEADERS.add("application/fhir+json");
  }

  /**
   * $export function.
   */
  @Override
  @Operation(name = JpaConstants.OPERATION_EXPORT,
      global = false /* set to true once we can handle this */, manualResponse = true,
      idempotent = true)
  public void export(
      @OperationParam(name = JpaConstants.PARAM_EXPORT_OUTPUT_FORMAT, min = 0, max = 1,
          typeName = "string") IPrimitiveType<String> theOutputFormat,
      @OperationParam(name = JpaConstants.PARAM_EXPORT_TYPE, min = 0, max = 1,
          typeName = "string") IPrimitiveType<String> theType,
      @OperationParam(name = JpaConstants.PARAM_EXPORT_SINCE, min = 0, max = 1,
          typeName = "instant") IPrimitiveType<Date> theSince,
      @OperationParam(name = JpaConstants.PARAM_EXPORT_TYPE_FILTER, min = 0, max = 1,
          typeName = "string") IPrimitiveType<String> theTypeFilter,
      ServletRequestDetails theRequestDetails) {

    authorize(theRequestDetails);
    super.export(theOutputFormat, theType, theSince, theTypeFilter, theRequestDetails);

  }

  /**
   * Group/Id/$export function.
   */
  @Override
  @Operation(name = JpaConstants.OPERATION_EXPORT, manualResponse = true, idempotent = true,
      typeName = "Group")
  public void groupExport(@IdParam IIdType theIdParam,
      @OperationParam(name = JpaConstants.PARAM_EXPORT_OUTPUT_FORMAT, min = 0, max = 1,
          typeName = "string") IPrimitiveType<String> theOutputFormat,
      @OperationParam(name = JpaConstants.PARAM_EXPORT_TYPE, min = 0, max = 1,
          typeName = "string") IPrimitiveType<String> theType,
      @OperationParam(name = JpaConstants.PARAM_EXPORT_SINCE, min = 0, max = 1,
          typeName = "instant") IPrimitiveType<Date> theSince,
      @OperationParam(name = JpaConstants.PARAM_EXPORT_TYPE_FILTER, min = 0, max = 1,
          typeName = "string") IPrimitiveType<String> theTypeFilter,
      @OperationParam(name = JpaConstants.PARAM_EXPORT_MDM, min = 0, max = 1,
          typeName = "boolean") IPrimitiveType<Boolean> theMdm,
      ServletRequestDetails theRequestDetails) {
    authorize(theRequestDetails);
    super.groupExport(theIdParam, theOutputFormat, theType, theSince, theTypeFilter, theMdm,
        theRequestDetails);

  }

  /**
   * Patient/$export function.
   */
  @Override
  @Operation(name = JpaConstants.OPERATION_EXPORT, manualResponse = true, idempotent = true,
      typeName = "Patient")
  public void patientExport(
      @OperationParam(name = JpaConstants.PARAM_EXPORT_OUTPUT_FORMAT, min = 0, max = 1,
          typeName = "string") IPrimitiveType<String> theOutputFormat,
      @OperationParam(name = JpaConstants.PARAM_EXPORT_TYPE, min = 0, max = 1,
          typeName = "string") IPrimitiveType<String> theType,
      @OperationParam(name = JpaConstants.PARAM_EXPORT_SINCE, min = 0, max = 1,
          typeName = "instant") IPrimitiveType<Date> theSince,
      @OperationParam(name = JpaConstants.PARAM_EXPORT_TYPE_FILTER, min = 0, max = 1,
          typeName = "string") IPrimitiveType<String> theTypeFilter,
      ServletRequestDetails theRequestDetails) {
    authorize(theRequestDetails);
    super.patientExport(theOutputFormat, theType, theSince, theTypeFilter, theRequestDetails);

  }

  /**
   * $export-poll-status function.
   */
  @Operation(name = JpaConstants.OPERATION_EXPORT_POLL_STATUS, manualResponse = true,
      idempotent = true)
  public void exportPollStatus(
      @OperationParam(name = JpaConstants.PARAM_EXPORT_POLL_STATUS_JOB_ID, typeName = "string",
          min = 0, max = 1) IPrimitiveType<String> theJobId,
      ServletRequestDetails theRequestDetails) throws IOException {

    HttpServletResponse response = theRequestDetails.getServletResponse();
    theRequestDetails.getServer().addHeadersToResponse(response);

    IBulkDataExportSvc.JobInfo status =
        myBulkDataExportSvc.getJobInfoOrThrowResourceNotFound(theJobId.getValueAsString());

    switch (status.getStatus()) {
      case SUBMITTED:
      case BUILDING:

        response.setStatus(Constants.STATUS_HTTP_202_ACCEPTED);
        response.addHeader(Constants.HEADER_X_PROGRESS,
            "Build in progress - Status set to " + status.getStatus() + " at "
                + new InstantType(status.getStatusTime()).getValueAsString());
        response.addHeader(Constants.HEADER_RETRY_AFTER, "120");
        break;

      case COMPLETE:

        response.setStatus(Constants.STATUS_HTTP_200_OK);
        response.setContentType(Constants.CT_JSON);

        // Create a JSON response
        BulkExportResponseJson bulkResponseDocument = new BulkExportResponseJson();
        bulkResponseDocument.setTransactionTime(status.getStatusTime());
        bulkResponseDocument.setRequest(status.getRequest());
        bulkResponseDocument.setRequiresAccessToken(true);

        for (IBulkDataExportSvc.FileEntry nextFile : status.getFiles()) {
          String serverBase = getServerBase(theRequestDetails);
          String nextUrl =
              serverBase + "/" + nextFile.getResourceId().toUnqualifiedVersionless().getValue();
          bulkResponseDocument.addOutput().setType(nextFile.getResourceType()).setUrl(nextUrl);
        }

        // UGLY FIX: call the getter which will make output an empty array instead of null for
        // purposes of writing to json
        bulkResponseDocument.getOutput();
        bulkResponseDocument.getError();

        JsonUtil.serialize(bulkResponseDocument, response.getWriter());
        response.getWriter().close();
        break;

      case ERROR:

        response.setStatus(Constants.STATUS_HTTP_500_INTERNAL_ERROR);
        response.setContentType(Constants.CT_FHIR_JSON);

        // Create an OperationOutcome response
        IBaseOperationOutcome oo = OperationOutcomeUtil.newInstance(myFhirContext);
        OperationOutcomeUtil.addIssue(myFhirContext, oo, "error", status.getStatusMessage(), null,
            null);
        myFhirContext.newJsonParser().setPrettyPrint(true).encodeResourceToWriter(oo,
            response.getWriter());
        response.getWriter().close();
    }
  }

  private String getServerBase(ServletRequestDetails theRequestDetails) {
    return StringUtils.removeEnd(theRequestDetails.getServerBaseForRequest(), "/");
  }

  // checks authorization and will throw Runtime Exceptions
  private void authorize(ServletRequestDetails theRequestDetails) {
    // confirm that header Accept value exists and is application/fhir+json
    System.out.println(theRequestDetails.getHeaders());
    String acceptHeader = theRequestDetails.getHeader(ACCEPT);
    if (!VALID_ACCEPT_HEADERS.contains(acceptHeader)) {
      String message = "Accept header was not provided or was invalid";

      InvalidRequestException invalidRequestException = new InvalidRequestException(message);
      List<String> responseAcceptHeaderValue = new ArrayList<String>();
      responseAcceptHeaderValue.add("application/json");
      invalidRequestException.getResponseHeaders().put(HttpHeaders.CONTENT_TYPE,
          responseAcceptHeaderValue);


      throw invalidRequestException;
    }
  }


}
