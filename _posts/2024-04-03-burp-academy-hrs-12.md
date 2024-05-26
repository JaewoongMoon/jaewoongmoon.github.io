---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Exploiting HTTP request smuggling to perform web cache deception"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-04-03 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-deception
- 취약점 설명페이지1: https://portswigger.net/web-security/request-smuggling
- 취약점 설명페이지2: https://portswigger.net/web-security/request-smuggling/exploiting
- 난이도: EXPERT (어려움)

# 취약점 개요 (HTTP 요청 스머글링을 통한 웹 캐시 디셉션)

1. 공격자는 다음과 같은 스머글링 요청을 보낸다. Content-Length 헤더에 지정된 43바이트는 Foo: X 까지의 길이이다.

![](/images/burp-academy-hrs-cache-deception-pattern.png)
*출처:https://portswigger.net/web-security/request-smuggling/exploiting#using-http-request-smuggling-to-perform-web-cache-deception*


2. 이어서 victim이 일반적인 정적인 리소스를 얻는 요청을 보낸다(`GET /static/some-image.png`). 백엔드 서버는 TE헤더를 보므로, 이 요청은 직전에 공격자가 보낸 `GET /private/messages` 요청에 이어져서 처리된다. 이 때 victim의 세션쿠키 값이 있으므로 victim 계정의 `GET /private/messages` 요청으로 처리된다! 

![](/images/burp-academy-hrs-cache-deception-pattern-2.png)
*출처:https://portswigger.net/web-security/request-smuggling/exploiting#using-http-request-smuggling-to-perform-web-cache-deception*

3. 그리고 프론트엔드 서버는 CL헤더를 보기 때문에 `GET /static/some-image.png`는 별도 요청으로 판단한다. 그 결과, 백엔드에서 처리된 victim의 `GET /private/messages`요청에 대한 응답이 정적리소스 `GET /static/some-image.png`에 대한 응답으로 캐싱된다. 

4. 공격자는 `GET /static/some-image.png`에 접근해서 victim의 개인정보를 입수한다. 


# 랩 개요
- 이 랩은 프론트 엔드 서버와 백엔드 서버로 구성되어 있다. 프론트 엔드 서버는 chunked encoding(TE헤더)을 지원하지 않는다. (즉, CL.TE패턴이다.)
- 프론트엔드 서버는 정적 리소스를 캐싱한다. 
- 랩을 풀려면 HTTP 요청 스머글링을 응용해서 victim의 API Key가 적혀있는 응답이 캐시되도록 만들어 API Key의 값을 알아낸 후, API Key를 제출하면 된다. 
- 랩에 접속한 후 30초동안 기다려야 한다. (victim의 API Key가 캐싱되도록 하기 위해서)
- wiener:peter로 로그인할 수 있다. 

```
This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. The front-end server is caching static resources.

To solve the lab, perform a request smuggling attack such that the next user's request causes their API key to be saved in the cache. Then retrieve the victim user's API key from the cache and submit it as the lab solution. You will need to wait for 30 seconds from accessing the lab before attempting to trick the victim into caching their API key.

You can log in to your own account using the following credentials: wiener:peter
```

# 풀이 
1. 일단 랩을 살펴본다. JS파일이나 이미지파일같은 정적 컨텐츠는 캐싱되는 것을 볼 수 있다. 

![](/images/burp-academy-hrs-12-1.png)

2. 다음으로 API Key를 얻을 수 있는 엔드포인트를 찾아본다. `GET /my-account?id=wiener` 로 접근하면 로그인한 계정의 API Key를 얻을 수 있는 것을 알 수 있다. 단순히 `GET /my-account`로 요청해도 응답이 돌아온다. 이 것을 이용하면 될 것 같다. 

![](/images/burp-academy-hrs-12-2.png)

3. 공격 페이로드를 만든다.

```http
POST / HTTP/1.1
Host: 0ae6003b03df40498dd891a200e9004c.web-security-academy.net
Content-Length: 37
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
Foo: X
```

4. 요청을 보내본다. 200응답이 확인된다. 이어서 victim이 랩에 접근한다면, 어딘가의 정적 리소스에 victim의 API키가 포함된 응답이 있을 것이다. 

![](/images/burp-academy-hrs-12-4.png)

5. 다시 랩의 홈으로 돌아간다. Burp의 History에서 찾아보면 `GET /resources/js/tracking.js` 요청의 응답에 관리자의 API Key가 포함된 것을 볼 수 있다. 

![](/images/burp-academy-hrs-12-3.png)

6. 이 API Key를 제출하면 문제가 풀린다. 

![](/images/burp-academy-hrs-12-success.png)



정리해본다. 다음 조건 하에서 공격이 성립한다 .
1. 프론트 엔드서버에 캐싱 기능이 있다. 일부 엔드포인트(정적파일 요청등)에서 이 캐싱이 사용된다.
2. API Key와 같은 중요정보를 제공하는 엔드포인트가 있다. 
3. HTTP 요청 스머글링이 가능하다. 

=> API Key를 얻는 요청을 스머글링하고, 바로 뒤 이어서 victim이 정적 파일을 요청하면, 정적 파일 요청에 대한 응답이 직전의 API Key를 얻는 요청에 대한 응답이 되어 캐싱된다. 공격자가 정적 파일에 접근하면 API Key가 노출된다. 