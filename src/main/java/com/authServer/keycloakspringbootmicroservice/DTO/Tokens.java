package com.authServer.keycloakspringbootmicroservice.DTO;

import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Tokens implements Serializable {
    String accessToken;
    String refreshToken;
}
