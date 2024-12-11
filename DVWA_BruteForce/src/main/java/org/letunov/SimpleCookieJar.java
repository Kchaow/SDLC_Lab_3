package org.letunov;

import okhttp3.Cookie;
import okhttp3.CookieJar;
import okhttp3.HttpUrl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SimpleCookieJar implements CookieJar {
    private final Map<String, Cookie> cookiesMap = new HashMap<>();

    @Override
    public void saveFromResponse(HttpUrl url, List<Cookie> cookies) {
        String securityCookieName = "security";
        cookies.forEach(cookie -> cookiesMap.put(cookie.name(), cookie));
        cookiesMap.computeIfPresent(securityCookieName, (k, securityCookie) -> new Cookie.Builder()
            .domain(securityCookie.domain())
            .expiresAt(securityCookie.expiresAt())
            .name(securityCookie.name())
            .expiresAt(securityCookie.expiresAt())
            .value("low")
            .build());
    }



    @Override
    public List<Cookie> loadForRequest(HttpUrl url) {
        List<Cookie> validCookies = new ArrayList<>();
        for (Cookie cookie : cookiesMap.values()) {
            if (cookie.matches(url)) {
                validCookies.add(cookie);
            }
        }
        return validCookies;
    }

    public Map<String, Cookie> getCookiesMap() {
        return cookiesMap;
    }
}