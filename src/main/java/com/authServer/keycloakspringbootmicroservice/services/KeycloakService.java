package com.authServer.keycloakspringbootmicroservice.services;

import java.util.Collections;
import java.util.List;

import com.authServer.keycloakspringbootmicroservice.model.User;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class KeycloakService {

    private final Keycloak keycloak;

    @Autowired
    public KeycloakService(Keycloak keycloak) {
        this.keycloak = keycloak;
    }

    private UserRepresentation getKeycloakUser(String username) {
        return keycloak.realm("Demo-Realm").users().search(username).get(0);
    }

    public void deleteKeycloakUser(String username) {
        UsersResource usersResource = (UsersResource) keycloak.realm("Demo-Realm").users();
        UserRepresentation user_To_Delete = usersResource.search(username).get(0);
        if (user_To_Delete != null) {
            String id = user_To_Delete.getId();
            usersResource.delete(id);
        }
    }

    public User updateKeycloakUser(String username, User user) {
        UserRepresentation user_To_Update = null;
        user_To_Update = getKeycloakUser(username);
        if (user_To_Update != null) {
            if (!user.getPassword().isBlank())
                keycloak.realm("Demo-Realm").users().get(user_To_Update.getId())
                        .resetPassword(createPasswordCredentials(user.getPassword()));
            user_To_Update.setEmailVerified(true);
            keycloak.realm("Demo-Realm").users().get(user_To_Update.getId()).update(user_To_Update);

        }
        return user;
    }

    public List<UserRepresentation> getAllUsers() {
        return keycloak.realm("Demo-Realm").users().list();
    }

    /* Keycloak business logic */

    public User addKeycloakUser(User user) {
        UsersResource usersResource = (UsersResource) keycloak.realm("Demo-Realm").users();
        CredentialRepresentation credentialRepresentation = createPasswordCredentials(user.getPassword());
        UserRepresentation kcUser = new UserRepresentation();
        kcUser.setUsername(user.getUsername());
        kcUser.setCredentials(Collections.singletonList(credentialRepresentation));
        kcUser.setEnabled(true);
        kcUser.setEmailVerified(true);
        usersResource.create(kcUser);
        return user;
    }

    private CredentialRepresentation createPasswordCredentials(String passwrd) {
        CredentialRepresentation passwoCredentials = new CredentialRepresentation();
        passwoCredentials.setTemporary(false);
        passwoCredentials.setType(CredentialRepresentation.PASSWORD);
        passwoCredentials.setValue(passwrd);
        return passwoCredentials;
    }

}
