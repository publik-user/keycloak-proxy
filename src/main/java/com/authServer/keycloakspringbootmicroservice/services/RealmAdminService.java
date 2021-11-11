package com.authServer.keycloakspringbootmicroservice.services;

import com.authServer.keycloakspringbootmicroservice.DTO.Tokens;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClient.RequestBodySpec;

@Service
public class RealmAdminService {
    private final WebClient.Builder builder;

    @Value("${keycloak.resource}")
    String clientId;
    @Value("${keycloak.credentials.secret}")
    String clientSecret;

    @Autowired
    public RealmAdminService(@Qualifier("getBuilder") WebClient.Builder builder) {
        this.builder = builder;
    }

    public Tokens getLoginToken(String username, String password) throws JSONException {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "password");
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);
        formData.add("username", username);
        formData.add("password", password);

        String token = ((RequestBodySpec) builder.build().post()
                .uri("http://localhost:8180/auth/realms/Demo-Realm/protocol/openid-connect/token")
                .body(BodyInserters.fromFormData(formData))).contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .retrieve().bodyToMono(String.class).block();

        JSONObject jsonObject = new JSONObject(token);

         return new Tokens(jsonObject.getString("access_token"),jsonObject.getString("refresh_token"));
        // jsonObject.getString("refresh_token"));
        //return jsonObject.getString("access_token");
    }

    /*
     * public String refreshLoginToken(String refreshToken) throws JSONException {
     * 
     * MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
     * formData.add("grant_type", "refresh_token"); formData.add("refresh_token",
     * refreshToken); formData.add("client_id", clientId);
     * formData.add("client_secret", clientSecret);
     * 
     * 
     * String token = ((RequestBodySpec) builder.build().post() .uri(
     * "http://localhost:8180/auth/realms/Demo-Realm/protocol/openid-connect/token")
     * .body(BodyInserters.fromFormData(formData))).contentType(MediaType.
     * APPLICATION_FORM_URLENCODED) .retrieve().bodyToMono(String.class).block();
     * 
     * JSONObject jsonObject = new JSONObject(token);
     * 
     * return jsonObject.getString("access_token"); }
     */
}
