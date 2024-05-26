---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Bypassing access controls via HTTP/2 request tunnelling"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-02-28 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. HTTP 프로토콜2를 사용하는 서버에 대한 스머글링을 사용한다.
- 문제 주소: https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling/lab-request-smuggling-h2-bypass-access-controls-via-request-tunnelling
- 취약점 설명페이지: https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling
- 난이도: EXPERT (어려움)

# Request Tunnelling 개요
- 지금까지의 스머글링은 프론트엔드 서버와 백엔드 서버가 커넥션을 공유하기 때문에 다른 유저에게 영향을 미치는 경우였다. 
- 어떤 시스템은 커넥션을 동일한 IP로부터 오는 경우에만 재사용하기도 한다. 이 경우, 이 커넥션은 해당 IP전용이 되므로 이 유저가 보낸 요청에 대해서만 응답이 보내진다. 일종의 전용터널처럼 된다. 다른 유저가 사용하는 터널에서 이 터널로는 간섭할 수 없는 것이다.
- 지금까지의 스머글링은 통하지 않지만, 이런 경우에도 보안 메커니즘을 우회하거나, 웹 캐시를 오염시키는 방식으로 공격이 가능한 경우가 있다. 

## Request tunnelling with HTTP/2
- 리퀘스트 터널링은 스머글링 요청에 대해서 응답이 두개 돌아오는지를 보고 판단가능하다. 
- 리퀘스트 터널링은 HTTP/1과 HTTP/2 양쪽 모두 가능하다. 하지만 HTTP/1쪽이 탐지가 어렵다. 
- 왜냐하면 HTTP/1에서는 기본적으로 지속되는 커넥션 속성 `keep-alive` 가 동작하기 때문에, 두개의 응답을 받았다고 해도 성공적으로 스머글링이 된 것인지 판단하기 어렵다. 
- 한편, HTTP/2에서는 각각의 스트림이 오직 하나의 요청과 응답을 포함하므로, HTTP/2 요청의 응답에 HTTP/1 응답이 섞여 있다면 성공적으로 스머글링을 수행(터널링)했다는 판단할 수 있다. 

## Request Tunnelling 을 통해 인터널 헤더 노출시키기 
HTTP/2 다운그레이딩이 가능하다면 인터널 헤더 노출이 가능해지는 경우가 있다. 

예를들어 다음과 같은 CRLF 인젝션 페이로드가 설정된 요청을 보자. 이 요청은 웹 어플리케이션에 댓글을 남기는 요청이다. 프론트 엔드 서버와 백엔드 서버는 둘다 이 것이 하나의 요청이라는 것에는 동의한다. 재미있는 점은 어디에서 헤더가 끝나는지에 대해서는 의견이 갈린다는 것이다. 

![인터널 헤더를 노출시키는 페이로드 예제](/images/burp-academy-hrs-17-16.png)

프론트 엔드는 HTTP/2 프로토콜을 따르므로 CRLF 인젝션 페이로드를 포함한 부분까지를 헤더로 본다. 따라서 `comment=` 이후에 인터널 헤더를 추가한다. 그러나 백엔드 서버는 HTTP/2 다운그레이드를 통해 HTTP/1 프로토콜을 따르므로 `comment=` 이전이 헤더의 끝이라고 인식한다. `comment=` 부터는 요청 바디로 인식하는 것이다. 그 결과, 프론트 엔드 서버에 의해 추가된 인터널 헤더를 포함해서 comment 파라메터의 값으로 인식하게 되고, 이 것을 댓글로 적게 된다. 적힌 댓글을 통해 인터널헤더의 값을 볼 수 있다. 백엔드 서버 입장에서 보는 요청은 다음과 같이 생겼다. 

```http
POST /comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 200

comment=X-Internal-Header: secretContent-Length: 3
x=1
```

## Blind request tunnelling
어떤 프론트 엔드 서버는 백엔드 서버로부터 받은 데이터를 모두 읽어들인다. 이 것은 만약 HTTP요청 터널링을 성공하면, 두개의 응답이 모두 클라이언트쪽으로 전송될 수도 있다는 것을 의미한다. 이 경우 메인요청에 대한 응답의 바디에 터널링한 요청의 응답이 포함되는 형태가 된다. 

다른 프론트엔드 서버는 백엔드서버로부터의 응답의 Content-Length 헤더에 지정된 바이트만큼만 읽는다. 따라서 오직 메인 요청에 대한 응답만 클라이언트에게 전달된다. 이는 블라인드 요청 터널링(Blind request tunneling)으로 이어진다. 스머글링 요청에 대한 응답이 없기 때문이다. 

## HEAD 메서드를 사용한 Non-blind request tunnelling 
블라인드 요청 터널링은 exploit하기 어렵지만, 가끔식 `HEAD`메서드를 사용해서 블라인드가 아니도록 (non-blind) 만들 수 있는 경우가 있다. HEAD 요청에 대한 응답 종종 바디가 없음에도 불구하고 Content-Length 헤더를 포함한다. 이는 동일한 엔드포인트에 GET메서드로 요청했을 경우의 바디의 크기를 나타낸다. 어떤 프론트 엔드 서버는 이 동작을 이해하지 못하고 Content-Length에 기술된 바이트만큼을 응답에서 읽어들인다. 이를 통해 스머글링한 요청에 대한 응답도 같이 포함되어 클라이언트에게 전달되는 경우가 있다. 


![HEAD 메서드를 사용한 Non-blind request tunnelling](/images/burp-academy-hrs-17-17.png)

메인 요청에 대한 응답의 Content-Length 헤더의 값에 따라 프론트엔드 서버의 동작이 달라진다. 예를 들어, 메인 응답의 Content-Length 헤더 값이 스머글링 응답의 크기보다 작으면, 스머글링 응답의 일부분만 보여질 것이다. 반대로 메인 응답의 Content-Length 헤더 값이 스머글링 응답의 크기보다 크면 프론트 엔드서버가 모자란 바이트만큼의 데이터가 오기를 계속 기다리므로 타임아웃이 발생한다. (따라서 아무런 데이터도 얻을 수 없다.) 

다행히도 다음과 같은 해결책이 존재한다. 
- 적절한 Content-Length 를 돌려주는 엔드포인트를 선정한다. 
- 만약 메인 응답의 크기가 너무 작으면, 메인 요청(HEAD 요청)의 바디에 의미없는 데이터를 추가해서 보낸다. 이러면 응답의 Content-Length 크기가 추가한만큼 커진다. (이는 요청 바디의 내용을 응답에 표시해주는 엔드포인트를 지정했을 때 가능하다. 예를들면 검색어를 화면에 보여주는 엔드포인트같은 경우다.)
- 만약 메인 응답의 크기가 너무 크면, 스머글링 요청의 바디에 의미없는 데이터를 추가해서 보낸다. 이를 통해 스머글링 응답의 크기를 메인 응답의 크기와 맞출 수 있다. 

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 프론트 엔드 서버는 HTTP/2 요청을 백엔드에 전송할 때 HTTP1으로 다운그레이드한다. 그리고 인커밍 헤더를 적절히 새니타이즈하지 못한다. 이로 인해서 스머글링이 가능하다. 
- 랩을 풀려면 admin패널에 접근하여 carlos유저를 삭제하면 된다. 
- 프론트 엔드 서버는 백엔드를 향한 커넥션을 재사용하지 않기 때문에 (유저에 따라 각각 다른 커넥션을 사용하기 때문에) 기존의 HTTP 요청 스머글링에 대해서는 취약하지 않다. 그렇지만 여전히 요청 터널링에 대해서는 취약하다. 
- 힌트: 프론트엔드 서버는 몇 개의 클라이언트 인증헤더를 들어오는 요청에 붙여준다. 문제를 풀려면 이 헤더들을 노출시키는 방법을 찾아야 한다. 

```
his lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming header names. To solve the lab, access the admin panel at /admin as the administrator user and delete the user carlos.

The front-end server doesn't reuse the connection to the back-end, so isn't vulnerable to classic request smuggling attacks. However, it is still vulnerable to request tunnelling.

Hint
The front-end server appends a series of client authentication headers to incoming requests. You need to find a way of leaking these.
```

# 풀이 시도
1. `HEAD /` 요청을 확인한다. 이 것을 기본형으로 사용할 것이다. 

![기본형 요청 확인](/images/burp-academy-hrs-17-1.png)

2. HTTP/2 헤더에 페이로드를 세팅한다. value에 이전 문제에서 배웠던 요청 splitting테크닉을 사용해서 개행문자`\r\n`를 세팅한다. 

![페이로드 세팅](/images/burp-academy-hrs-17-1.png)

3. 그런데 요청을 보내보면 `RST_STREAM received with error code: 0x1 (Protocol error detected)`라는 프로토콜 에러 응답이 돌아온다. 

![프로토콜 에러 응답](/images/burp-academy-hrs-17-3.png)

4. 몇 번 테스트 해보니 HTTP/2 헤더에 `\r\n`가 하나만 있더라도 저 에러가 발생하는 것을 알았다. 음.. 해결방법을 모르겠다. 

5. 답을 보고 푼다. 다음과 같이 기본형 요청(GET / )에다가 Foo 헤더를 추가한다. 

![프로토콜 에러 응답](/images/burp-academy-hrs-17-4.png)

6. 그리고 Foo 헤더의 값이 아닌 이름에 CRLF 인젝션을 시도한다. 이름을 `foo: bar\r\nHost: abc`로 지정하고 값은 아무거나 상관없다. `xyz`로 준다. 그러자 다음과 같이 Host abc에 접근할 때 504 Gateway Timeout 에러가 발생했다는 에러 메세지가 돌아온다. CRLF 인젝션이 성공한 것이다! 

**이번 문제는 HTTP/2헤더의 값 뿐만 아니라 이름에도 인젝션할 수 있다는 것을 알려주고 있다.**

![프로토콜 에러 응답](/images/burp-academy-hrs-17-5.png)

7. 상품 검색 화면을 보면 검색어를 응답에 보여주는 것을 알 수 있다.  

![상품 검색 결과](/images/burp-academy-hrs-17-14.png)

8. 이 기능을 이용한다. foo 헤더의 이름에 다음과 같이 페이로드를 지정한다. Content-Length의 값을 500으로 좀 길게 설정한다. 

```http
foo: bar\r\n
Content-Length: 500\r\n
\r\n
search=x
```

![foo헤더에 페이로드 지정](/images/burp-academy-hrs-17-6.png)

메서드도 GET에서도 POST로 변경한다. 

![메서드 변경](/images/burp-academy-hrs-17-8.png)

CLRF 인젝션을 통해 백엔드 서버가 보는 요청은 다음과 같은 형태일 것이다. 

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

search=xX-Internal-Header: secretContent-Length: xxx
x=1
```

9. 요청을 보내본다. 처음에는 타임아웃 에러가 발생한다. 이는 요청 바디의 값이 백엔드 서버가 기대하는 값 (CLRF 인젝션으로 삽입한 CL헤더의 값 500)보다 작아서 계속 기다리기 때문에 그런 것이다. 

![타임아웃 발생](/images/burp-academy-hrs-17-15.png)

10. 바디의 값이 500바이트보다 큰 값이 되도록 랜덤한 값을 적절히 채워서 보내면 다음과 같이 응답이 바뀐다. 프론트엔드 서버가 추가한 헤더 값이 검색결과에 나타난다! ✨ 

![프론트엔드 서버가 추가하는 값 확인](/images/burp-academy-hrs-17-7.png)

11. 스머글링용 요청에 이 헤더들을 추가해서 /admin으로 접근하는 요청을 만든다. HTTP요청 메서드는 `HEAD` 로 바꾼다. 

![admin패널에 접근하는 스머글링 요청](/images/burp-academy-hrs-17-9.png)

12. 요청을 보내보면 기대하는 크기보다 적은 바이트가 전송되었다는 에러 메세지가 돌아온다. 이는 메인 요청의 응답 크기(8504 바이트)가 스머글링 요청의 응답크기(3608바이트)보다 크기 때문이다. 

![HEAD요청 결과 확인](/images/burp-academy-hrs-17-10.png)

13. 메인 요청의 경로를 /login 으로 바꾼다. /login 의 응답 크기가 적절하기 때문이다. 변경 후에 요청을 보내보면 HEAD 메서드인데도 HTTP 터널링이 성공해서 스머글링한 요청의 응답이 회신되는 것을 볼 수 있다. 

![요청경로 변경 후 응답](/images/burp-academy-hrs-17-11.png)

HTTP응답의 하단 부분을 보면 관리자 기능의 경로도 회신된 것을 볼 수 있다. 

![admin패널 확인](/images/burp-academy-hrs-17-12.png)

14. 스머글링 요청에 carlos 유저를 삭제하는 경로를 지정한다. 

![carlos유저 삭제 요청](/images/burp-academy-hrs-17-13.png)

15. 요청을 보내본다. 응답 자체는 500 에러가 돌아오지만 스머글링한 요청을 서버에서 처리된다. 웹 브라우저를 보면 풀이에 성공했다는 메세지가 표시된다. 

```htt[]
HTTP/2 500 Internal Server Error
Content-Type: text/html; charset=utf-8
Content-Length: 150

<html><head><title>Server Error: Proxy error</title></head><body><h1>Server Error: Received only 372 of expected 3247 bytes of data</h1></body></html>
```


![풀이 성공](/images/burp-academy-hrs-17-success.png)
