---
layout: post
title: "Burp Academy-웹 캐시 포이즈닝 관련 취약점: Web cache poisoning with multiple headers"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Web Cache Poisoning]
toc: true
last_modified_at: 2023-12-26 09:50:00 +0900
---

# 개요
- 웹 캐시 포이즈닝 취약점을 이용한 문제이다. 
- 문제 주소: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-multiple-headers
- 취약점 설명페이지1: https://portswigger.net/web-security/web-cache-poisoning
- 취약점 설명페이지2: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws
- 난이도: PRACTITIONER (보통)

# 웹 캐시 개념 / 용어
- 웹 캐시에는 캐시 키(Cache Key)라는 개념이 있다. 유저로부터의 요청이 자신이 캐시하고 있는 요청과 동일한 요청인지를 판단하고, 동일한 요청이라면 백엔드 서버에 요청을 보내지 않고 캐시한 요청에 대한 응답을 유저에게 회신한다. 
- 웹 캐시는 HTTP요청 중 몇 가지 요소를 기준으로 동일한 요청인지를 판단한다. (보통 Host 헤더나 요청 패스등이다.)
- 어떤 HTTP 요청이 웹 캐시의 판단 기준에 매칭되는 요청이라면 "keyed"라고 하고, 그 반대라면 "unkeyed"라고 한다. 

# 랩 개요
- 여러 개의 헤더를 사용한 경우에 웹 캐시 포이즈닝 공격이 가능하다. 
- 일반 유저가 정기적으로 랩 사이트를 방문한다. 
- HTTP응답을 캐시시켜, 일반 유저에게 alert(document.cookie) 코드를 실행시키면 랩이 풀린다. 
- 힌트: 이 랩은 `X-Forwarded-Host` 헤더와 `X-Forwarded-Scheme`헤더를 지원한다.

```
This lab contains a web cache poisoning vulnerability that is only exploitable when you use multiple headers to craft a malicious request. A user visits the home page roughly once a minute. To solve this lab, poison the cache with a response that executes alert(document.cookie) in the visitor's browser.
Hint
This lab supports both the X-Forwarded-Host and X-Forwarded-Scheme headers.
```

# 도전
1. 이 랩에는 exploit 서버가 주어져 있다. 

2. 랩을 관찰해본다. `X-Forwarded-Host` 헤더와 `X-Forwarded-Scheme`헤더가 동시에 있고,  `X-Forwarded-Scheme`헤더의 값이 https가 아니면  `X-Forwarded-Host` 헤더에 설정한 도메인으로 302응답을 해주는 것을 볼 수 있다. 이 것을 악용하면 exploit서버로 리다이렉트 시킬 수 있을 것이다. 

![랩 관찰](/images/burp-academy-wcp-3-1.png)

3. exploit서버의 /exploit 경로에 접근하면 다음과 같은 응답이 회신되도록 만든다. 자바스크립트가 동작하여 alert창이 뜰 것이다.

![exploit 서버 구성](/images/burp-academy-wcp-3-2.png)

4. 웹 캐시 포이즈닝을 시도한다. 성공적으로 웹 캐시를 변경시킨 것을 알 수 있다. 

```http
X-Forwarded-Host: exploit-0aba00de03f97df28355811401e1005d.exploit-server.net/exploit
X-Forwarded-Scheme: http
```

![웹 캐시 포이즈닝 시도](/images/burp-academy-wcp-3-3.png)

5. 웹 브라우저로 랩에 접근해보면 exploit서버로 리다이렉트되어 alert창이 뜨는 것을 볼 수 있다. 

![웹 캐시 포이즈닝 결과](/images/burp-academy-wcp-3-4.png)

6. 그러나 문제풀이에 성공했다는 메세지는 출력되지 않는다. 출제측이 원하는 답이 아닌 것이다. 

# 답보고 풀이

1. 답에서는 `/resources/js/tracking.js` 에 대한 응답을 포이즈닝하는 것으로 나와있다. 아하! 곰곰히 생각해보니 내 답은 alert창이 뜨는 도메인이 exploit서버의 도메인이다. 랩서버의 도메인에서 자바스크립트가 동작하지 않으면 쿠키를 얻어낼 수가 없다. 따라서 자바스크립트가 동작하는 도메인은 랩 서버의 도메인이어야 한다. 

2. exploit서버를 구성한다. `/resources/js/tracking.js`요청이 오면 alert코드를 서비스하도록 만든다. 

![exploit서버 구성](/images/burp-academy-wcp-3-5.png)

3. `/resources/js/tracking.js`요청에 대한 응답을 오염시킨다. 

![웹 캐시 포이즈닝 재시도](/images/burp-academy-wcp-3-5.png)

4. 잠시 기다리면 문제 풀이에 성공했다는 메세지가 출력된다. 

![풀이 성공](/images/burp-academy-wcp-3-success.png)