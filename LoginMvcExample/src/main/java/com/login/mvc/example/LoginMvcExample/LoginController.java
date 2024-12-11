package com.login.mvc.example.LoginMvcExample;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@Controller
@RequiredArgsConstructor
public class LoginController {
    private final AuthenticationManager authenticationManager;
    private static final Random random = new Random();
    private static final Map<String, String> CAPTCHA_VALUE = Map.of("1", "DVWA", "2", "1_42L", "3", "MIREA", "4", "SECURE", "5", "58VK");
    private static final Map<String, Long> SESSION_LOGIN_TRIES = new HashMap<>();
    private static final Map<String, String> SESSION_CAPTCHA = new HashMap<>();
    private static final int TRIES_LIMIT = 5;
    private static final String IS_CAPTCHA_ATTR = "isCaptcha";
    private static final String CAPTCHA_NUM_ATTR = "captchaNum";
    private static final String LOGIN_MESSAGE_ATTR = "loginMessage";

    @GetMapping("/login")
    public String login(@RequestParam(required = false) String username,
        @RequestParam(required = false) String password,
        @RequestParam(name="Login", required = false) String login,
        @RequestParam(name="captcha", required = false) String captchaValue,
        HttpServletRequest request, Model model) {

        System.out.println("Incoming request: " + request.getQueryString());

        HttpSession session = request.getSession(true);
        var sessionId = session.getId();

        if (username == null || password == null || login == null) {
            return "login";
        }

        if (SESSION_CAPTCHA.containsKey(sessionId)) {
            model.addAttribute(IS_CAPTCHA_ATTR, true);
            model.addAttribute(CAPTCHA_NUM_ATTR, SESSION_CAPTCHA.get(session.getId()));
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(authToken);
        } catch (AuthenticationException e) {
            SESSION_LOGIN_TRIES.put(session.getId(), 1 + SESSION_LOGIN_TRIES.getOrDefault(session.getId(), 0L));
            if (SESSION_LOGIN_TRIES.get(sessionId) > TRIES_LIMIT) {
                model.addAttribute(IS_CAPTCHA_ATTR, true);
                var captchaNum = random.nextInt(1, 6) + "";
                SESSION_CAPTCHA.put(sessionId,  captchaNum);
                model.addAttribute(CAPTCHA_NUM_ATTR, captchaNum);
            }
            model.addAttribute(LOGIN_MESSAGE_ATTR, "Username and/or password incorrect.");
            return "login";
        }
        if (SESSION_CAPTCHA.containsKey(session.getId()) && (captchaValue == null || !captchaValue.equals(CAPTCHA_VALUE.get(SESSION_CAPTCHA.get(sessionId))))) {
            return "login";
        }
        SESSION_LOGIN_TRIES.put(session.getId(), 0L);
        SESSION_CAPTCHA.remove(session.getId());
        model.addAttribute(IS_CAPTCHA_ATTR, false);
        model.addAttribute(LOGIN_MESSAGE_ATTR, "Welcome to the password protected area admin");
        SecurityContextHolder.getContext().setAuthentication(authentication);

        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

        return "login";
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }
}