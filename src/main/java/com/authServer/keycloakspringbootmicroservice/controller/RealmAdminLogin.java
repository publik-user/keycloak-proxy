package com.authServer.keycloakspringbootmicroservice.controller;

import com.authServer.keycloakspringbootmicroservice.DTO.Credentials;
import com.authServer.keycloakspringbootmicroservice.DTO.Tokens;
import com.authServer.keycloakspringbootmicroservice.services.RealmAdminService;

import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/realm-admin")
public class RealmAdminLogin {
    private final RealmAdminService realmAdminService;

    public RealmAdminLogin(RealmAdminService realmAdminService) {
        this.realmAdminService = realmAdminService;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<Tokens> authenticate(@RequestBody Credentials credentials) {
        Tokens token = null;

        try {
            token = realmAdminService.getLoginToken(credentials.getUsername(), credentials.getPassword());
        } catch (JSONException e) {
            e.printStackTrace();
        }

        return new ResponseEntity<>(token, HttpStatus.OK);
    }

    /*
     * @PostMapping("/refresh_Auth") public ResponseEntity<String>
     * refreshAuth(@RequestBody String token) { String newToken = ""; try { newToken
     * = realmAdminService.refreshLoginToken(token); } catch (JSONException e) {
     * e.printStackTrace(); }
     * 
     * return new ResponseEntity<>(newToken, HttpStatus.OK); }
     */
}
