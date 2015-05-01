package org.ubicollab.ubibazaar.jaas;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.security.auth.login.LoginException;

import org.mindrot.jbcrypt.BCrypt;

import com.sun.appserv.security.AppservPasswordLoginModule;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;

public class UbibazaarLoginModule extends AppservPasswordLoginModule {

  public UbibazaarLoginModule() {
    System.out.println("Constructing UbibazaarLoginModule...");
  }

  @Override
  protected void authenticateUser() throws LoginException {
    String username = getUsername();
    String password = new String(getPasswordChar());

    // DEBUG
    // System.out.println("UbibazaarLoginModule authenticating user " + username + " with password "
    // + password + " on realm " + getCurrentRealm().getName());

    // check if we are in the right realm
    if (!(getCurrentRealm() instanceof UbibazaarRealm)) {
      throw new LoginException("Realm is not UbibazaarRealm. Check 'login.conf'.");
    }

    UbibazaarRealm realm = (UbibazaarRealm) getCurrentRealm();

    // authenticate user
    if (!doAuthentication(username, password, realm)) {
      // Login failed
      throw new LoginException("UbibazaarLoginModule failed authentication for " + username);
    }

    // authentication successful
    // DEBUG
    // System.out.println("UbibazaarLoginModule successful authentication for " + username);

    // find groups of this user
    Enumeration<String> groupEnumeration = null;
    try {
      groupEnumeration = realm.getGroupNames(username);
    } catch (InvalidOperationException e) {
      throw new LoginException("InvalidOperationException in UbibazaarLoginModule");
    } catch (NoSuchUserException e) {
      throw new LoginException("User " + username + " probably does not have any group set");
    }

    // transform one stupid format into another through list
    List<String> groupList = new ArrayList<String>();
    while (groupEnumeration != null && groupEnumeration.hasMoreElements())
      groupList.add((String) groupEnumeration.nextElement());

    String[] groupArray = groupList.toArray(new String[groupList.size()]);

    commitUserAuthentication(groupArray);
  }

  private boolean doAuthentication(String username, String candidate, UbibazaarRealm realm) {
    String sql = "select u.password from user u where u.username = ? ";

    try (Connection conn = realm.getConnection();
        PreparedStatement ps = conn.prepareStatement(sql)) {
      ps.setString(1, username);
      ps.execute();

      try (ResultSet rs = ps.getResultSet()) {
        if (rs.next()) {
          String hashed = rs.getString("password");
          return BCrypt.checkpw(candidate, hashed);
        } else {
          // no such user
          return false;
        }
      }
    } catch (SQLException e) {
      e.printStackTrace();
      return false;
    }
  }
}
