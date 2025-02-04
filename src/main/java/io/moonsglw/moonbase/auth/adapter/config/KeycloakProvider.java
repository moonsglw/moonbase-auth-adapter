package io.moonsglw.moonbase.auth.adapter.config;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import io.moonsglw.moonbase.auth.adapter.exception.UnauthorizedException;
import io.moonsglw.moonbase.auth.adapter.service.TokenCache;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter
@Configuration
public class KeycloakProvider {

    @Value("${keycloak.auth-server-url}")
    public String serverURL;

    @Value("${keycloak.realm}")
    public String realm;

    @Value("${keycloak.resource}")
    public String authAdapterClientId;

    @Value("${keycloak.credentials.secret}")
    public String authAdapterClientSecret;

    @Autowired
    private TokenCache tokenCache;

    private static Keycloak keycloak = null;

    public KeycloakProvider() {
    }

    public Keycloak getInstance() {
        if (keycloak == null) {
            return KeycloakBuilder.builder()
                    .realm(realm)
                    .serverUrl(serverURL)
                    .clientId(authAdapterClientId)
                    .clientSecret(authAdapterClientSecret)
                    .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                    .build();
        }
        return keycloak;
    }

    public KeycloakBuilder newKeycloakBuilderWithPasswordCredentials(String username, String password) {
        return KeycloakBuilder.builder()
                .realm(realm) 
                .serverUrl(serverURL)
                .clientId(authAdapterClientId)
                .clientSecret(authAdapterClientSecret)
                .username(username)
                .password(password);
    }

    public AccessTokenResponse generateClientToken(String clientId, String clientSecret) {
        try {
            Keycloak keycloakClient = KeycloakBuilder.builder()
                    .serverUrl(serverURL)
                    .realm(realm)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                    .build();

            return keycloakClient.tokenManager().getAccessToken();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate client token from Keycloak", e);
        }
    }
    public boolean validateToken(String token, String clientId) {
        try {
            DecodedJWT decodedJWT = JWT.decode(token);
            Date expiryDate = decodedJWT.getExpiresAt();

            if (expiryDate != null && expiryDate.before(new Date())) {
                log.warn("Token for client {} has expired.", clientId);
                return false;
            }

            String issuer = decodedJWT.getIssuer();
            if (!issuer.equals(serverURL + "/realms/" + realm)) {
                log.warn("Invalid token issuer for client {}", clientId);
                return false;
            }

            return true;
        } catch (Exception e) {
            log.error("Token validation failed for client {}: {}", clientId, e.getMessage());
            return false;
        }
    }

    public String getClientIdFromToken(String token) {
        try {
            DecodedJWT decodedJWT = JWT.decode(token);
            return decodedJWT.getClaim("azp").asString();
        } catch (Exception e) {
            throw new UnauthorizedException("Error decoding the token.");
        }
    }
    
    public boolean validateUserToken(String token) {
        try {
            DecodedJWT decodedJWT = JWT.decode(token);
            Date expiryDate = decodedJWT.getExpiresAt();

            if (expiryDate == null || expiryDate.before(new Date())) {
                log.warn("User token has expired.");
                return false;
            }

            String issuer = decodedJWT.getIssuer();
            if (!issuer.equals(serverURL + "/realms/" + realm)) {
                log.warn("Invalid token issuer.");
                return false;
            }

            return true;
        } catch (Exception e) {
            log.error("User token validation failed: {}", e.getMessage());
            return false;
        }
    }
    
    public String getUserIdFromToken(String token) {
        try {
            DecodedJWT decodedJWT = JWT.decode(token);
            return decodedJWT.getSubject();  // "sub" (Subject) contains user ID
        } catch (Exception e) {
            log.error("Error extracting user ID from token: {}", e.getMessage());
            return null;
        }
    }

    public String getUsernameFromToken(String token) {
        try {
            DecodedJWT decodedJWT = JWT.decode(token);
            return decodedJWT.getClaim("preferred_username").asString();  // Extract username
        } catch (Exception e) {
            log.error("Error extracting username from token: {}", e.getMessage());
            return null;
        }
    }

    public List<String> getUserRolesFromToken(String token) {
        try {
            DecodedJWT decodedJWT = JWT.decode(token);
            Claim realmAccess = decodedJWT.getClaim("realm_access");

            if (realmAccess.isNull()) {
                return Collections.emptyList();
            }

            return realmAccess.asMap().get("roles") != null 
                ? (List<String>) realmAccess.asMap().get("roles") 
                : Collections.emptyList();

        } catch (Exception e) {
            log.error("Error extracting roles from token: {}", e.getMessage());
            return Collections.emptyList();
        }
    }
    
    /*public boolean validateToken(String token, String clientId, String clientSecret) throws UnirestException {
        String url = serverURL + "/realms/" + realm + "/protocol/openid-connect/token/introspect";

        JsonNode response = Unirest.post(url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .field("client_id", clientId)
                .field("client_secret", clientSecret)
                .field("token", token)
                .field("token_type_hint", "access_token")
                .asJson()
                .getBody();

        return response.getObject().optBoolean("active", false);
    }


    public long getTokenExpiry(String clientId, String clientSecret) {
        try {
            Keycloak keycloakClient = KeycloakBuilder.builder()
                    .serverUrl(serverURL)
                    .realm(realm)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                    .build();

            AccessTokenResponse tokenResponse = keycloakClient.tokenManager().getAccessToken();
            return tokenResponse.getExpiresIn();
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch token expiry from Keycloak", e);
        }
    }*/
}

