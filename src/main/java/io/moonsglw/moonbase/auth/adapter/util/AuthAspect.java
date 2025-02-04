package io.moonsglw.moonbase.auth.adapter.util;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.moonsglw.moonbase.auth.adapter.exception.UnauthorizedException;
import io.moonsglw.moonbase.auth.adapter.intrface.RequiresAuth;
import io.moonsglw.moonbase.auth.adapter.service.KeycloakService;
import lombok.extern.slf4j.Slf4j;

@Aspect
@Component
@Slf4j
public class AuthAspect {

    private final KeycloakService kcAdminClient;

    public AuthAspect(KeycloakService kcAdminClient) {
        this.kcAdminClient = kcAdminClient;
    }

    @Before("@annotation(requiresAuth)")
    public void validateToken(JoinPoint joinPoint, RequiresAuth requiresAuth) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new UnauthorizedException("Missing or invalid Authorization header");
        }

        String token = authHeader.replace("Bearer ", "");

        String clientId = kcAdminClient.getClientIdFromToken(token);
        if (clientId != null) {
            if (!kcAdminClient.validateToken(token, clientId)) {
                throw new UnauthorizedException("Invalid or expired client token.");
            }
            ClientContext.setClientId(clientId);
            return;
        }

        // Otherwise, treat as a user token
        if (!kcAdminClient.validateUserToken(token)) {
            throw new UnauthorizedException("Invalid or expired user token.");
        }
        
        // Extract user details
        String userId = kcAdminClient.getUserIdFromToken(token);
        String username = kcAdminClient.getUsernameFromToken(token);
        List<String> roles = kcAdminClient.getUserRolesFromToken(token);

        // Store in UserContext
        UserContext.setUser(userId, username, roles);
        log.info("Authenticated user: {} (ID: {}) with roles: {}", username, userId, roles);
    
    }

    @After("@annotation(io.moonsglw.moonbase.auth.adapter.intrface.RequiresAuth)")
    public void clearContext() {
        // Ensure no data leaks between requests
        ClientContext.clear();
        UserContext.clear();
    }
}





