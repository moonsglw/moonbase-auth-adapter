package io.moonsglw.moonbase.auth.adapter.service;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class TokenCache {

    private final Map<String, CachedToken> tokenStore = new ConcurrentHashMap<>();

    @Value("${token.cache.cleanup.rate.ms}")
    private long cleanupRate;

    @Value("${token.expiry.buffer.sec}")
    private int expiryBufferSeconds;

    public void storeToken(String clientId, String token, long expiresAt) {
        tokenStore.put(clientId, new CachedToken(token, expiresAt));
        log.info("Stored token for clientId: {} with expiry: {}", clientId, expiresAt);
    }

    public String getToken(String clientId) {
        CachedToken cachedToken = tokenStore.get(clientId);
        if (cachedToken != null && System.currentTimeMillis() / 1000 < cachedToken.getExpiresAt()) {
            return cachedToken.getToken();
        }
        return null; // Token expired or not found
    }

    public long getExpiresAt(String clientId) {
        CachedToken cachedToken = tokenStore.get(clientId);
        return cachedToken != null ? cachedToken.getExpiresAt() : 0;
    }

    public void clearToken(String clientId) {
        tokenStore.remove(clientId);
        log.info("Cleared token for clientId: {}", clientId);
    }

    @Scheduled(fixedRateString = "${token.cache.cleanup.rate.ms}")
    public void cleanupExpiredTokens() {
        long now = System.currentTimeMillis() / 1000; // Convert to seconds
        Iterator<Map.Entry<String, CachedToken>> iterator = tokenStore.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, CachedToken> entry = iterator.next();
            if (entry.getValue().getExpiresAt() < now) {
                log.info("Removing expired token for client: {}", entry.getKey());
                iterator.remove();
            }
        }
    }

    private static class CachedToken {
        private final String token;
        private final long expiresAt;

        public CachedToken(String token, long expiresAt) {
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
}

