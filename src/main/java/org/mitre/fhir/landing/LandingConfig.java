package org.mitre.fhir.landing;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import ca.uhn.fhir.to.FhirTesterMvcConfig;
import ca.uhn.fhir.to.TesterConfig;

// simplified copy of config from ca.uhn.fhir.jpa.starter.FhirTesterConfig
@Import(FhirTesterMvcConfig.class)
@ComponentScan(basePackages = {"org.mitre.fhir.landing"})
public class LandingConfig {

  @Bean
  public TesterConfig testerConfig() {
    TesterConfig retVal = new TesterConfig();
    return retVal;
  }
}

