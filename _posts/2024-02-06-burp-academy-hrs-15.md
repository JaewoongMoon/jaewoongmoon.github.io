---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: HTTP/2 request splitting via CRLF injection"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-02-19 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 여기서부터는 HTTP 프로토콜2를 사용하는 서버에 대한 스머글링을 사용한다.Advanced 토픽이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-smuggling-via-crlf-injection
- 취약점 설명페이지1: https://portswigger.net/web-security/request-smuggling/advanced#http-2-request-splitting
- 취약점 설명페이지2: https://portswigger.net/web-security/request-smuggling/advanced/http2-exclusive-vectors
- 난이도: PRACTITIONER (보통)

# 취약점 개요 (Request smuggling via CRLF injection)
- HTTP/2에서는 개행문자(`\r\n`)가 특별한 의미를 가지지 않기 때문에 다음과 같은 식으로 헤더의 값에 사용할 수도 있다. 

```
foo	bar\r\nTransfer-Encoding: chunked
```

위의 예에서  만약 백엔드에서 프로토콜이 HTTP/1.1로 다운그레이드된다면 델리미터(`\r\n`)가 특별한 의미를 가지기 때문에 TE헤더가 추가되는 효과가 나타난다. 


# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 프론트 엔드 서버는 HTTP/2 요청을 백엔드에 전송할 때 HTTP1으로 다운그레이드한다. 그리고 들어오는 헤더를 적절히 새니타이즈하지 못한다. 이로 인해서 스머글링이 가능하다. 
- 랩을 풀려면 CLRF 인젝션과 같은 `HTTP/2-exclusive request smuggling vector` 를 사용해서 다른 유저의 계정으로 접근하면 된다. 
- victim은 15초마다 웹 사이트를 방문한다. 

```
This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming headers.

To solve the lab, use an HTTP/2-exclusive request smuggling vector to gain access to another user's account. The victim accesses the home page every 15 seconds.

If you're not familiar with Burp's exclusive features for HTTP/2 testing, please refer to the documentation for details on how to use them.
```


# 풀이 시도
## 스머글링 가능한지 확인
음... 스머글링 자체가 안되는 것 같다. 아무리 시도해도 200응답만 돌아온다. 

하루 고민해보고 원인을 알았다. Inspector를 보니 transfer-encoding 헤더가 별도의 헤더로 인식되고 있었다. 

![TE헤더 확인](/images/burp-academy-hrs-15-0.png)

내가 원하는 건 HTTP/2의 foo헤더의 값으로 TE헤더를 넣는 것이다. 이는 Inspector에서 화살표 버튼을 클릭하면 수정가능하다. 

![HTTP/2헤더 값 변경버튼](/images/burp-academy-hrs-15-0-1.png)

다음과 같이 foo헤더의 값으로 TE헤더를 넣을 수 있다. 

![foo헤더의 값으로 TE헤더 넣기](/images/burp-academy-hrs-15-1.png)

HTTP/2 헤더를 변경하면 Repeater에서도 Pretty탭이 비활성화된다. 

foo 헤더의 값을 `bar\r\nTransfer-Encoding: chunked\r\n`로 했을 때는 돌아오는 응답이 항상 `400 Bad Request`다. 

![400응답](/images/burp-academy-hrs-15-2.png)

위의 값에서 마지막 `\r\n`을 없애면 이번에는 항상 200응답이 돌아온다. 

![200응답](/images/burp-academy-hrs-15-3.png)

이를 통해 CRLF 인젝션 자체는 가능한 것을 알 수 있다.  `\r\n`가 있고 없고에 따라 서버 반응이 달라지기 때문에 서버에서 처리되고 있다는 것을 유추할 수 있기 때문이다. 

음.. 모르겠다. 답을 보자. 

# 답보고 풀이 
아하. 대충 방법을 알았다. 웹사이트에는 검색어를 세션별로 저장해서 보여주는 기능이 있다. HRS를 악용하면 다른 유저의 응답을 여기에 기록할 수 있다. 그것을 보고 세션을 훔치는 것이다. 

1. 검색어 이력 기능을 확인한다. 다른 세션으로 접근하면 검색이력이 나오지 않는 것으로 보아 검색어는 세션에 묶여있는 것을 확신할 수 있다. 

![검색어 이력 확인](/images/burp-academy-hrs-15-4.png)

2. 스머글링을 이용하면 이 검색어 이력에 다른 사용자의 요청을 기록할 수 있을 것이다. 일단 필요없는 헤더들을 삭제하고 다음과 같은 기본형을 만들어 둔다. `Foo: bar` 헤더도 추가해두었다.

![HTTP 리퀘스트 스머글링 기본형 만들기](/images/burp-academy-hrs-15-5.png)

3. Foo헤더의 값에 CRLF 인젝션을 이용한 페이로드 `\r\nTransfer-Encoding: chunked` 를 추가해준다.

![CRLF 인젝션을 이용한 페이로드 준비](/images/burp-academy-hrs-15-6.png)

4. 그러면 Request 탭이 Pretty에서 Raw로 고정된다. 추가한 CRLF를 화면에서 표시할 수 없기 때문이다.

![CRLF 헤더 적용하기](/images/burp-academy-hrs-15-7.png)

5. 스머글링(밀반입)할 요청을 만든다. 쿠키 세션값을 공격자의 것으로 세팅해야 한다. 그래야 공격자의 검색이력화면에서 값을 확인할 수 있기 때문이다. 요청을 보내보면 200응답이 확인된다.

![스머글링 요청 만들기](/images/burp-academy-hrs-15-8.png)

6. 웹 브라우저에서 화면을 리로드해본다. 스머글링한 요청이 처리되어 검색어로 다른 유저의 요청의 일부가 처리된 것을 볼 수 있다. 

![스머글링 테스트](/images/burp-academy-hrs-15-9.png)

7. Content-Length 헤더의 값을 조금씩 늘려가면서 결과를 확인해본다. 

![CL헤더 변경](/images/burp-academy-hrs-15-10.png)

8. Content-Length 헤더 값이 850일 때의 스머글링 결과다. victim의 세션ID가 검색 결과 화면에서 확인되었다. ✨

![ victim의 세션ID](/images/burp-academy-hrs-15-11.png)

9. 이 세션ID로 랩 서버에 요청을 보낸 후에 웹 페이지를 리로드하면 문제 풀이에 성공했다는 메세지가 출력된다. 

![풀이 성공](/images/burp-academy-hrs-15-success.png)
