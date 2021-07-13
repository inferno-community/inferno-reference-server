package org.mitre.fhir;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.context.FhirVersionEnum;
import ca.uhn.fhir.jpa.api.config.DaoConfig;
import ca.uhn.fhir.jpa.api.dao.IFhirSystemDao;
import ca.uhn.fhir.jpa.bulk.export.provider.BulkDataExportProvider;
import ca.uhn.fhir.jpa.provider.TerminologyUploaderProvider;
import ca.uhn.fhir.jpa.provider.r4.JpaSystemProviderR4;
import ca.uhn.fhir.jpa.search.DatabaseBackedPagingProvider;
import ca.uhn.fhir.rest.api.EncodingEnum;
import ca.uhn.fhir.rest.server.ETagSupportEnum;
import ca.uhn.fhir.rest.server.RestfulServer;
import ca.uhn.fhir.rest.server.interceptor.LoggingInterceptor;
import ca.uhn.fhir.rest.server.provider.ResourceProviderFactory;
import ca.uhn.fhir.rest.server.util.ISearchParamRegistry;
import javax.servlet.ServletException;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Meta;
import org.mitre.fhir.authorization.FakeOauth2AuthorizationInterceptorAdaptor;
import org.mitre.fhir.authorization.ServerConformanceWithAuthorizationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

/**
 * MitreJpaServer configures the server.
 *
 * @author Tim Shaffer
 */

public class MitreJpaServer extends RestfulServer {
  private static final long serialVersionUID = 1L;

  @Autowired
  protected ISearchParamRegistry searchParamRegistry;
  
  @Autowired
  BulkDataExportProvider bulkDataExportProvider;


  public MitreJpaServer() {
    // Required for Autowiring searchParamRegistry
    SpringBeanAutowiringSupport.processInjectionBasedOnCurrentContext(this);
  }

  @Override
  protected void initialize() throws ServletException {
    super.initialize();

    // Setup a FHIR context.
    FhirVersionEnum fhirVersion = FhirVersionEnum.R4;
    setFhirContext(new FhirContext(fhirVersion));

    // Get the Spring context from the web container (it's declared in web.xml)
    ApplicationContext appContext = (ApplicationContext) getServletContext()
        .getAttribute("org.springframework.web.context.WebApplicationContext.ROOT");

    // myResourceProvidersR4 is generated as a part of hapi-fhir-jpaserver-base.
    // It contains bean definitions for a resource provider for each resource type.
    ResourceProviderFactory resourceProviders =
        appContext.getBean("myResourceProvidersR4", ResourceProviderFactory.class);
    registerProviders(resourceProviders.createProviders());

    // mySystemProviderR4 is generated as a part of hapi-fhir-jpaserver-base.
    // The system provider implements non-resource-type methods,
    // such as transaction, and global history.
    JpaSystemProviderR4 systemProvider =
        appContext.getBean("mySystemProviderR4", JpaSystemProviderR4.class);
    registerProvider(systemProvider);

    // mySystemDaoR4 is generated as a part of hapi-fhir-jpaserver-base.
    // The conformance provider exports the supported resources,
    // search parameters, etc for this server.
    // The JPA version adds resource counts to the exported statement, so it is a nice addition.
    @SuppressWarnings("unchecked")
    IFhirSystemDao<Bundle, Meta> systemDao =
        appContext.getBean("mySystemDaoR4", IFhirSystemDao.class);

    ServerConformanceWithAuthorizationProvider confProvider =
        new ServerConformanceWithAuthorizationProvider(this, systemDao,
            appContext.getBean(DaoConfig.class), searchParamRegistry);
    confProvider.setImplementationDescription("HAPI FHIR R4 Server");
    setServerConformanceProvider(confProvider);
    
    

    // Enable e-tag support.
    setETagSupport(ETagSupportEnum.ENABLED);

    // Default to JSON and pretty printing
    setDefaultPrettyPrint(true);
    setDefaultResponseEncoding(EncodingEnum.JSON);

    // This configures the server to page search results to
    // and from the database, instead of only to memory.
    // This may mean a performance hit when performing searches that return lots of results,
    // but makes the server much more scalable.
    setPagingProvider(appContext.getBean(DatabaseBackedPagingProvider.class));

    // If you are using DSTU3+, you may want to add a terminology uploader.
    // This allows uploading of external terminologies such as Snomed CT.
    // It does not have any security attached (any anonymous user may use it by default).
    // Consider using an AuthorizationInterceptor with this feature.
    registerProvider(appContext.getBean(TerminologyUploaderProvider.class));

    // Add logging interceptor.
    LoggingInterceptor loggingInterceptor = new LoggingInterceptor();
    loggingInterceptor.setLoggerName("fhir.access");
    loggingInterceptor
        .setMessageFormat("Path[${servletPath}] " + "Source[${requestHeader.x-forwarded-for}] "
            + "Operation[${operationType} ${operationName} ${idOrResourceName}] "
            + "UA[${requestHeader.user-agent}] " + "Params[${requestParameters}] "
            + "ResponseEncoding[${responseEncodingNoDefault}]");
    registerInterceptor(loggingInterceptor);

    registerInterceptor(new FakeOauth2AuthorizationInterceptorAdaptor());
    
    //enable Bulk Export
    registerProvider(bulkDataExportProvider);

    
    
  }
  
}
