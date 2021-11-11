package com.authServer.keycloakspringbootmicroservice.controller;

import java.util.List;

import javax.annotation.security.RolesAllowed;

import com.authServer.keycloakspringbootmicroservice.model.User;
import com.authServer.keycloakspringbootmicroservice.services.KeycloakService;

import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/usersManagement")
public class KeycloakSignupController {
    private final KeycloakService keycloakService;

    public KeycloakSignupController(KeycloakService keyclkService) {
        keycloakService = keyclkService;
    }

    @PostMapping("/addNewUser")
    public ResponseEntity<User> addUser(@RequestBody User user) {
        User u = keycloakService.addKeycloakUser(user);
        return new ResponseEntity<>(u, HttpStatus.OK);
    }

    @DeleteMapping("/deleteUser/{username}")
    public ResponseEntity<?> deleteUser(@PathVariable("username") String username) {
        keycloakService.deleteKeycloakUser(username);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PutMapping("/updateUser/{username}")
    public ResponseEntity<User> updateKeycloakUser(@PathVariable("username") String username, @RequestBody User user) {
        keycloakService.updateKeycloakUser(username, user);
        return new ResponseEntity<>(user, HttpStatus.OK);
    }

    @RolesAllowed("demo-realm-admin")
    @GetMapping("/getAllUsers")
    public ResponseEntity<List<UserRepresentation>> getAllUsers() {
        List<UserRepresentation> userList = keycloakService.getAllUsers();
        return new ResponseEntity<>(userList, HttpStatus.OK);
    }
}
