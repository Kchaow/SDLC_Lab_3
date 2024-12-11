<?php

if( isset( $_GET[ 'Login' ] ) ) {

	$user = $_GET[ 'username' ];

	$pass = $_GET[ 'password' ];
    //CWE-327 Use of a Broken or Risky Cryptographic Algorithm. Не рекомендуется использование таких старых алгоритмов хеширования как MD4, MD5, SHA1, DES, так как их значительно легче сломать, чем современные
	$pass = md5( $pass ); 

    //CWE-89 'SQL Injection'. В username можно ввести "admin' OR '1'='1", что позволит войти с любым паролем
	$query  = "SELECT * FROM `users` WHERE user = 'admin' AND password = '$pass';";
    //CWE-200 Exposure of Sensitive Information to an Unauthorized Actor. В случае ошибки выполнения запроса пользователю выводится фрагмент внутреннего устройства кода, что может быть использовано злоумышленниками
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
	if( $result && mysqli_num_rows( $result ) == 1 ) {

		$row    = mysqli_fetch_assoc( $result );
		$avatar = $row["avatar"];

        //CWE-79 'Cross-site Scripting'. Прямое использование значения в html разметке без предварительной обработки может привести к внедрению html тегов пользователями на веб-странице.
        //Например, в комбинации с CWE-89 в страницу можно внедрить плеер из Яндекс Музыки введя в username: admin' OR '<iframe frameborder="0" allow="clipboard-write" style="border:none;width:100%;height:210px;" width="100%" height="210" src="https://music.yandex.ru/iframe/track/71237781/12115632">Слушайте <a href=\'https://music.yandex.ru/album/12115632/track/71237781\'>No Gods</a> — <a href=\'https://music.yandex.ru/artist/5704222\'>FREE FLOW FLAVA</a> на Яндекс Музыке</iframe>
		$html .= "<p>Welcome to the password protected area {$user}</p>";
		$html .= "<img src=\"{$avatar}\" />";
	}
	else {

		$html .= "<pre><br />Username and/or password incorrect.</pre>";
	}
	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}
?>