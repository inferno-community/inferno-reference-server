package org.mitre.fhir;

import ca.uhn.fhir.jpa.api.config.DaoConfig;
import ca.uhn.fhir.jpa.batch.config.NonPersistedBatchConfigurer;
import ca.uhn.fhir.jpa.config.BaseJavaConfigR4;
import ca.uhn.fhir.jpa.dao.DaoSearchParamProvider;
import ca.uhn.fhir.jpa.model.config.PartitionSettings;
import ca.uhn.fhir.jpa.model.entity.ModelConfig;
import ca.uhn.fhir.jpa.searchparam.registry.ISearchParamProvider;
import ca.uhn.fhir.jpa.searchparam.registry.ISearchParamRegistry;
import ca.uhn.fhir.jpa.searchparam.registry.SearchParamRegistryImpl;
import ca.uhn.fhir.rest.server.interceptor.ResponseHighlighterInterceptor;
import java.sql.Driver;
import java.util.Properties;
import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import org.apache.commons.dbcp2.BasicDataSource;
import org.springframework.batch.core.configuration.annotation.BatchConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Configures the Server and Database.
 * 
 * @author Tim Shaffer
 */
@Configuration
@EnableTransactionManagement
public class MitreServerConfig extends BaseJavaConfigR4 {

  /**
   * Returns the Data Access Object (DAO) configuration.
   * 
   * @return the DAO configuration.
   */
  @Bean
  public DaoConfig daoConfig() {
    DaoConfig config = new DaoConfig();
    config.setAllowExternalReferences(true);
    config.getTreatBaseUrlsAsLocal().add("http://hl7.org/fhir/us/core/");
    return config;
  }

  /**
   * Returns the model configuration.
   * 
   * @return the model configuration
   */
  @Bean
  public ModelConfig modelConfig() {
    return daoConfig().getModelConfig();
  }

  /**
   * Returns the data source for the server.
   * 
   * @return the data source
   */
  @Bean
  public DataSource dataSource() {

    BasicDataSource dataSource = new BasicDataSource();

    try {
      // org.apache.derby.jdbc.EmbeddedDriver
      HapiReferenceServerProperties hapiReferenceServerProperties =
          new HapiReferenceServerProperties();


      String driverName = hapiReferenceServerProperties.getDataSourceDriver();
      Driver driver = (Driver) Class.forName(driverName).getConstructor().newInstance();
      dataSource.setDriver(driver);

      String url = hapiReferenceServerProperties.getDataSourceUrl();
      dataSource.setUrl(url);

      String username = hapiReferenceServerProperties.getDataSourceUsername();
      dataSource.setUsername(username);

      String password = hapiReferenceServerProperties.getDataSourcePassword();
      dataSource.setPassword(password);

      String schema = hapiReferenceServerProperties.getDataSourceSchema();
      if (schema != null) {
        dataSource.setDefaultSchema(schema);
      }
      return dataSource;
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(0);
    }

    return dataSource;
  }

  /**
   * Returns the LocalContainerEntityMangerFactoryBean.
   * 
   * @return the LocalContainerEntityMangerFactoryBean
   */
  @Override
  @Bean
  public LocalContainerEntityManagerFactoryBean entityManagerFactory() {
    LocalContainerEntityManagerFactoryBean manager = super.entityManagerFactory();
    manager.setPersistenceUnitName("HAPI_PU");
    manager.setDataSource(dataSource());
    manager.setJpaProperties(jpaProperties());

    return manager;
  }

  private Properties jpaProperties() {

    HapiReferenceServerProperties hapiReferenceServerProperties =
        new HapiReferenceServerProperties();

    Properties properties = new Properties();
    properties.put("hibernate.dialect", hapiReferenceServerProperties.getHibernateDialect());
    properties.put("hibernate.format_sql", hapiReferenceServerProperties.getHibernateFormatSql());
    properties.put("hibernate.show_sql", hapiReferenceServerProperties.getHibernateShowSql());
    properties.put("hibernate.hbm2ddl.auto",
        hapiReferenceServerProperties.getHibernateHbdm2ddlAuto());
    properties.put("hibernate.jdbc.batch_size",
        hapiReferenceServerProperties.getHibernateJdbcBatchSize());
    properties.put("hibernate.cache.use_query_cache",
        hapiReferenceServerProperties.getHibernateCacheUseQueryCache());
    properties.put("hibernate.cache.use_second_level_cache",
        hapiReferenceServerProperties.getHibernateCacheUseSecondLevelCache());
    properties.put("hibernate.cache.use_structured_entries",
        hapiReferenceServerProperties.getHibernateCacheUseStructuredEntries());
    properties.put("hibernate.cache.use_minimal_puts",
        hapiReferenceServerProperties.getHibernateCacheUseMinimalPuts());

    properties.put("hibernate.search.model_mapping",
        hapiReferenceServerProperties.getHibernateSearchModelMapping());
    properties.put("hibernate.search.default.directory_provider",
        hapiReferenceServerProperties.getHibernateSearchDefaultDirectoryProvider());
    properties.put("hibernate.search.default.indexBase",
        hapiReferenceServerProperties.getHibernateSearchDefaultIndexBase());
    properties.put("hibernate.search.lucene_version",
        hapiReferenceServerProperties.getHibernateSearchLuceneVersion());

    return properties;

  }

  @Bean
  public ResponseHighlighterInterceptor responseHighlighterInterceptor() {
    return new ResponseHighlighterInterceptor();
  }

  // Beans that are autowired in other places
  @Bean
  public PartitionSettings partitionSettings() {
    PartitionSettings retVal = new PartitionSettings();
    return retVal;
  }
  
  @Bean
  public BatchConfigurer batchConfigurer() {
      return new NonPersistedBatchConfigurer();
  }
  

  @Primary
  @Bean
  public JpaTransactionManager hapiTransactionManager(EntityManagerFactory entityManagerFactory) {
      JpaTransactionManager retVal = new JpaTransactionManager();
      retVal.setEntityManagerFactory(entityManagerFactory);
      return retVal;
  }

  @Bean
  public ISearchParamProvider mySearchParamProvider() {
    return new DaoSearchParamProvider();
  }

  // Required for MitreJpaServer
  @Bean
  public ISearchParamRegistry searchParamRegistry() {
    return new SearchParamRegistryImpl();
  }
}
