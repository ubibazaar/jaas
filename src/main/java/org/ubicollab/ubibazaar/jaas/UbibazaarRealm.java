package org.ubicollab.ubibazaar.jaas;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Set;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import com.google.common.collect.Sets;
import com.sun.appserv.security.AppservRealm;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;

public class UbibazaarRealm extends AppservRealm {

  private String DATASOURCE_CONTEXT;

  public UbibazaarRealm() {
    System.out.println("Constructing UbibazaarRealm...");
  }

  @Override
  public void init(Properties properties) {
    System.out.println("Initializing UbibazaarRealm...");

    // propagate properties to realm
    String jaasContext = properties.getProperty("jaas-context");
    if (jaasContext != null) {
      setProperty("jaas-context", jaasContext);
    }

    // load data source
    DATASOURCE_CONTEXT = properties.getProperty("datasource_jndi_name");
  }

  @Override
  public String getAuthType() {
    return "BASIC";
  }

  @Override
  public Enumeration<String> getGroupNames(String username)
      throws InvalidOperationException, NoSuchUserException {

    if (isManager(username)) {
      return Collections.enumeration(Collections.singletonList("manager"));
    }

    String sql = ""
        + "select ug.group_name "
        + "from user u "
        + "join user_group ug on u.id = ug.user_id "
        + "where u.username = ? ";

    try (Connection conn = getConnection();
        PreparedStatement ps = conn.prepareStatement(sql)) {
      ps.setString(1, username);
      ps.execute();

      try (ResultSet rs = ps.getResultSet()) {
        Set<String> results = Sets.newHashSet();

        while (rs.next()) {
          results.add(rs.getString("group_name"));
        }

        if (results.isEmpty()) {
          throw new NoSuchUserException("User " + username
              + "does not exist or does not have a role");
        }

        return Collections.enumeration(results);
      }
    } catch (SQLException e) {
      e.printStackTrace();
      return null;
    }
  }

  public boolean isManager(String username) {
    return username.matches("^[0-91-f]{32}$");
  }

  public Connection getConnection() throws SQLException {
    Connection result = null;
    try {
      Context initialContext = new InitialContext();
      DataSource datasource = (DataSource) initialContext.lookup(DATASOURCE_CONTEXT);
      if (datasource != null) {
        result = datasource.getConnection();
      }
      else {
        System.out.println("Failed to lookup datasource going by name " + DATASOURCE_CONTEXT);
      }
    } catch (NamingException ex) {
      System.out.println("Cannot get connection for " + DATASOURCE_CONTEXT + ": " + ex);
    } catch (SQLException ex) {
      System.out.println("Cannot get connection for " + DATASOURCE_CONTEXT + ": " + ex);
    }
    return result;
  }
}
