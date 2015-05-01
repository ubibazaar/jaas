# Ubibazaar API JAAS realm
JAAS (Java Authentication and Authorization Service) realm for Ubibazaar API.

For authentication to work on deployed API, you need a new realm type to be added to the application server and then an authentication realm needs to be created.

1. First of all, locate your glassfish installation and open directory ``{glassfish}/domains/domain1``. We will call this one ``{domain-dir}`` for the purpose of this installation guide.

2. Copy ``ubibazaar-jaas-0.1.jar`` to ``{domain-dir}/lib``

3. To do this, open ``domain.xml`` configuration file, usually found in ``{domain-dir}/config``. Locate the other auth-realms in the file and add this one along:
  ```xml
  <auth-realm 
    classname="org.ubicollab.ubibazaar.jaas.UbibazaarRealm" 
    name="ubibazaar-api-realm">
      <property name="jaas-context" value="ubibazaarRealm"></property>
      <property name="datasource_jndi_name" value="jdbc/ubibazaar"></property>
  </auth-realm>
  ```
  Do make sure you are adding them to the *server-config* part and not the *default-config*.

4. Then open ``login.conf`` in the same directory and append these lines to the end of your file.
  ```
  ubibazaarRealm {
     org.ubicollab.ubibazaar.jaas.UbibazaarLoginModule required;
  };
  ```

5. Restart Glassfish
