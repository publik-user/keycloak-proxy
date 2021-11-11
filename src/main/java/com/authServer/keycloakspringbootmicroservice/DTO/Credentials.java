package com.authServer.keycloakspringbootmicroservice.DTO;

import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class Credentials implements Serializable {
    private String username;
    private String password;
}
