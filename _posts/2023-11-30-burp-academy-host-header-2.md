---
layout: post
title: "Burp Academy-Host 헤더 관련 취약점: Performing CSRF exploits over GraphQL"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Host헤더]
toc: true
last_modified_at: 2023-12-04 09:50:00 +0900
---

# 개요
- HTTP Host 헤더 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass
- 취약점 설명페이지 1: https://portswigger.net/web-security/host-header
- 취약점 설명페이지 2: https://portswigger.net/web-security/host-header/exploiting#accessing-restricted-functionality
- 난이도: APPRENTICE (쉬움)

# 취약점 개요
- 조직 내부로부터의 요청만 허용하기 위해 Host헤더의 값을 기준으로 접근제한을 하는 경우 간단히 우회가 가능하다. 

# 문제 개요
- 이 랩은 Host 헤더의 값으로 권한 제어를 하고 있다. 
- admin패널로 접ㄱ든해서 carlos유저를 삭제하면 문제가 풀린다.

```
This lab makes an assumption about the privilege level of the user based on the HTTP Host header.

To solve the lab, access the admin panel and delete the user carlos.
```

# 풀이
1. `/admin`으로 요청을 보내보면 응답에서 local유저만 접근이 가능하다는 메세지를 볼 수 있다. 

![admin 엔드포인트 요청결과](/images/burp-academy-host-header-2-1.png)

2. Host헤더를 localhost로 지정한 후 요청을 보내보면 `/admin`에 접근이 가능한 것을 알 수 있다. 

![Host헤더 변조후 요청결과](/images/burp-academy-host-header-2-2.png)

3. carlos유저를 삭제하는 링크로 요청을 보낸다. 처리가 성공하고 302 응답이 회신되는 것을 볼 수 있다. 

![carlos유저삭제](/images/burp-academy-host-header-2-3.png)

4. 문제가 풀렸다. 😃

![풀이 성공](/images/burp-academy-host-header-2-success.png)