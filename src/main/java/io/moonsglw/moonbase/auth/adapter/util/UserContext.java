package io.moonsglw.moonbase.auth.adapter.util;

import java.util.List;

public class UserContext {
    private static final ThreadLocal<String> userIdHolder = new ThreadLocal<>();
    private static final ThreadLocal<String> usernameHolder = new ThreadLocal<>();
    private static final ThreadLocal<List<String>> rolesHolder = new ThreadLocal<>();

    public static void setUser(String userId, String username, List<String> roles) {
        userIdHolder.set(userId);
        usernameHolder.set(username);
        rolesHolder.set(roles);
    }

    public static String getUserId() {
        return userIdHolder.get();
    }

    public static String getUsername() {
        return usernameHolder.get();
    }

    public static List<String> getRoles() {
        return rolesHolder.get();
    }

    public static void clear() {
        userIdHolder.remove();
        usernameHolder.remove();
        rolesHolder.remove();
    }
}

