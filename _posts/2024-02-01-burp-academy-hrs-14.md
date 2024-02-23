---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Response queue poisoning via H2.TE request smuggling"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-02-06 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 여기서부터는 HTTP 프로토콜2를 사용하는 서버에 대한 스머글링을 사용한다.Advanced 토픽이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling
- 취약점 설명페이지: https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning
- 난이도: PRACTITIONER (보통)

# 취약점 개요 (Response queue poisoning)
- 꽤 임팩트가 크다. 프론트엔드 서버와 백엔드 사이에 사용하는 응답 큐가 오염되면, 공격자는 본래 다른 유저에게 갈 응답을 캡쳐할 수 있다. 
- 응답큐가 오염되었다는 것은 중간에 다른 요청이 끼어듬으로 인해 순서가 하나씩 다 밀리는 현상이다.
- 하나씩 다 밀리므로 웹 사이트의 마지막 요청을 보낸 사용자에게 본래 보낼 응답은 큐에 남아 있는 상태가 된다. 
- 이 때 공격자가 웹 사이트에 요청을 보내면 어떻게 될까? 위의 마지막 유저의 응답을 가로챌 수 있다. 여기에 세션토큰과 같은 중요정보가 포함되어 있다면 어카운트 탈취로 이어질 수 있다. 

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 프론트 엔드 서버는 HTTP/2 요청을 백엔드에 전송할 때 HTTP1으로 다운그레이드한다. 이로 인해서 스머글링이 가능하다. 
- 랩을 풀려면 응답 큐 포이즈닝(response queue poisoning)을 이용해서 admin패널에 접근하여 carlos유저를 삭제하면 된다. 
- admin은 15초마다 웹 사이트를 방문한다. 
```
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests even if they have an ambiguous length.

To solve the lab, delete the user carlos by using response queue poisoning to break into the admin panel at /admin. An admin user will log in approximately every 15 seconds.

The connection to the back-end is reset every 10 requests, so don't worry if you get it into a bad state - just send a few normal requests to get a fresh connection.
```

# 풀이 시도
1. H2.CL 타입의 체크용 페이로드를 보내본다. 


```http
POST / HTTP/2
Host: 0ae20076039ab2c58192750a008d00fe.web-security-academy.net
Cookie: session=DDz3ojK0oI01wDQhGx8bCokRKjTdUwnX
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Content-Length: 0

GET /404 HTTP/1.1
Host: 0ae20076039ab2c58192750a008d00fe.web-security-academy.net
Content-Length: 5

x=1
```

2. 그런데 이번에는 200응답밖에 돌아오지 않는다. 스머글링이 안되고 있는 것이다. 왜일까? 

3. 확장 프로그램 HTTP Request Smuggler 를 써본다. 어허.. 그런데 웬걸. 이 스캐너로도 탐지가 안된다! 

4. 실제로는 되고 있는 것인지도 모른다. Burp Intruder로 지속적으로 요청을 보내고 응답을 확인해봤다. 수백개 전달해봤지만 응답이 동일하다. 스머글링이 안되고 있는 것 같다. 

어쩔 수 없다. 답을 본다. 

# 답 보고 풀이
아아.. 이번 문제는 H2.TE 타입이었다. H2.CL 용 페이로드를 보내도 반응이 없었을 만하다.

## 스머글링되는 것을 확인
H2.TE 타입 페이로드로 스머글링이 되는 것을 확인했다. 이 페이로드를 보내면 세번째응답에서 404응답이 회신된다.

```http
POST / HTTP/2
Host: 0a3900cb047389a4877bdf20009d0087.web-security-academy.net
Transfer-Encoding: chunked

0

SMUGGLED
```

![H2.TE 타입 페이로드로 스머글링이 되는 것을 확인](/images/burp-academy-hrs-14-1.png)

## 관리자 페이지 스머글링시도

관리자 페이지(`GET /admin HTTP/1.1`)에 접근해본다. 그러면 400 Bad Request 응답이 회신된다. 이는 Host헤더의 끝에 개행문자(\r\n)가 하나만 있기 때문이다.

![admin 페이지에 접근시도1](/images/burp-academy-hrs-14-2.png)

하나 더 추가해서 Host헤더의 끝을 \r\n\r\n로 만들면 제대로 동작한다. 이번엔 `HTTP/2 401 Unauthorized`가 회신된다. 

```tttp
POST / HTTP/2
Host: 0a3900cb047389a4877bdf20009d0087.web-security-academy.net
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: 0a3900cb047389a4877bdf20009d0087.web-security-academy.net


```

![admin 페이지에 접근시도2](/images/burp-academy-hrs-14-3.png)

## 관리자 세션 토큰 훔치기 
정답에는 다음 테크닉이 소개되어 있다. 원래의 HTTP 요청도 404응답이 오는 경로 (GET /x) 를 지정하고, 스머글링하는 요청에서 동일하게 404응답이 오는 경로 (GET /x) 를 지정하는 테크닉이다. 이러면 HTTP 응답 큐 포이즈닝이 성공해서 다른 유저의 응답을 받게 되면 404응답이 아니게 되므로 응답코드를 보고 스머글링이 성공했는지를 알 수 있다. 

![404응답 확인](/images/burp-academy-hrs-14-4.png)

요청을 계속해서 보내야하므로 Intruder를 사용하면 좋다. 페이로드는 Null payloads를 선택하고 횟수는 적당히 500번 반복을 지정한다. 

![Intruder설정-페이로드](/images/burp-academy-hrs-14-5.png)

리소는 풀은 Concurrent requests(동시 요청수) 를 1로, 딜레이는 1초로 준다. 

![Intruder설정-리소스풀](/images/burp-academy-hrs-14-6.png)

Attack을 클릭해서 공격을 수행한다. 30x번대 응답이 왔을 때만 보여주도록 필터링을 걸어두면 보기 편하다. 144번째 요청에서 302응답이 확인되었다. 관리자 계정의 세션 토큰이 보이는 것을 알 수 있다. 

![관리자토큰획득](/images/burp-academy-hrs-14-7.png)

이 세션토큰을 사용해서 관리자 페이지에 접근한다. 접근에 성공하면 유저 삭제 링크가 보이는 것을 알 수 있다. 

![관리자 페이지 접근 성공](/images/burp-academy-hrs-14-8.png)


carlos 유저를 삭제한다. 성공하면 302응답이 돌아오고 문제 풀이에 성공했다는 메세지가 표시된다. 

![carlos 유저 삭제](/images/burp-academy-hrs-14-9.png)

![풀이 성공](/images/burp-academy-hrs-14-success.png)





