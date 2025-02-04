package io.moonsglw.moonbase.auth.adapter.util;

public class ClientContext {
    private static final ThreadLocal<String> CLIENT_ID_THREAD_LOCAL = new ThreadLocal<>();

    public static void setClientId(String clientId) {
        CLIENT_ID_THREAD_LOCAL.set(clientId);
    }

    public static String getClientId() {
        return CLIENT_ID_THREAD_LOCAL.get();
    }

    public static void clear() {
        CLIENT_ID_THREAD_LOCAL.remove();
    }
}

