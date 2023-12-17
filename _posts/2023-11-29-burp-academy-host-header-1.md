---
layout: post
title: "Burp Academy-Host 헤더 관련 취약점: Performing CSRF exploits over GraphQL"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Host헤더]
toc: true
last_modified_at: 2023-11-30 09:50:00 +0900
---

# 개요
- HTTP Host 헤더 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-basic-password-reset-poisoning
- 취약점 설명페이지 1: https://portswigger.net/web-security/host-header
- 취약점 설명페이지 2: https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
- 난이도: APPRENTICE (쉬움)

# 취약점 개요 
- HTTP Host 헤더의 목적은 클라언트가 통신하고자 하는 백엔드 컴포넌트를 식별하기 위함이다. 
- 호스트 헤더 인젝션을 통해 여러 종류의 공격을 할 수 있다. 
- 예를 들면 비밀번호 재설정 요청을 보내는 서버를 호스트 헤더 인젝션을 통해 해커의 서버로 지정할 수 있다. 

# 문제 개요
- 이 랩은 password reset poisoning 취약점이 있다. 
- Carlos 유저는 자신에게 온 메일의 링크는 무조건 클릭한다. 
- Carlos 유저의 계정으로 로그인하면 문제가 풀린다. 

```
This lab is vulnerable to password reset poisoning. The user carlos will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account.

You can log in to your own account using the following credentials: wiener:peter. Any emails sent to this account can be read via the email client on the exploit server.
```

# 풀이
1. 먼저 비밀번호 재설정화면을 살펴본다. 

![비밀번호 재설정 화면](/images/burp-academy-host-header-1-1.png)

버튼을 누르면 `POST /forgot-password` 엔드포인트로 요청이 전송되는 것을 볼 수 있다.  화면에는 `Please check your email for a reset password link.` 라고 표시된다. 

2. exploit서버에서 이메일 클라이언트를 클릭하면 도착한 메일을 볼 수 있다. 다음과 같이 비밀번호 재설정 링크와 토큰이 붙어있는 것을 볼 수 있다.

![도착한 메일 확인](/images/burp-academy-host-header-1-2.png)

3. 이제 Host헤더 인젝션을 실시한다. 비밀번호 재설정 요청을 Repeater로 보내고 Host 헤더를 exploit서버의 도메인으로 변경한다. 그리고 username은 carlos로 바꾸고 요청을 전송한다. 그러면 요청이 정상적으로 처리되는 것을 볼 수 있다. 

![Host헤더 인젝션 실시](/images/burp-academy-host-header-1-3.png)

4. exploit서버의 접근 로그를 확인해보면 다음과 같이 carlos유저가 이메일 링크를 클릭한 이력을 볼 수 있다. (Host헤더 인젝션을 통해 exploit서버로 요청이 전달된다.)

![접근 로그 확인](/images/burp-academy-host-header-1-4.png)

5. 이 요청 링크를 문제 서버의 도메인에 붙여서 웹 브라우저로 접속하면 다음과 같이 carlos유저의 비밀번호 재설정 화면이 나타난다. 

![비밀번호 재설정화면](/images/burp-academy-host-header-1-5.png)

6. 비밀번호를 재설정하고 carlos유저로 로그인하면 문제가 풀린다. 

![풀이성공](/images/burp-academy-host-header-1-success.png)
