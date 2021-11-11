package com.authServer.keycloakspringbootmicroservice.services;

import org.keycloak.admin.client.Keycloak;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class KeycloakGroupService {
    private final Keycloak keycloak;

    @Autowired
    public KeycloakGroupService(Keycloak keycloak) {
        this.keycloak = keycloak;
    }

    

    
}
