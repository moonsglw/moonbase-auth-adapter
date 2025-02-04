package io.moonsglw.moonbase.auth.adapter.dto;

public class TokenResponseDTO {
    private String token;
    private long expiresAt; // Unix timestamp when the token expires

    public TokenResponseDTO(String token, long expiresAt) {
        this.token = token;
        this.expiresAt = expiresAt;
    }

    public String getToken() {
        return token;
    }

    public long getExpiresAt() {
        return expiresAt;
    }
}

