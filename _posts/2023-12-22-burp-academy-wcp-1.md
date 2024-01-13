---
layout: post
title: "Burp Academy-웹 캐시 포이즈닝 관련 취약점: Web cache poisoning with an unkeyed header"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Web Cache Poisoning]
toc: true
last_modified_at: 2023-12-22 09:50:00 +0900
---

# 개요
- 웹 캐시 포이즈닝 취약점을 이용한 문제이다. 
- 문제 주소: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header
- 취약점 설명페이지: https://portswigger.net/web-security/web-cache-poisoning
- 난이도: PRACTITIONER (보통)

# 웹 캐시 개념 / 용어
- 웹 캐시에는 캐시 키(Cache Key)라는 개념이 있다. 유저로부터의 요청이 자신이 캐시하고 있는 요청과 동일한 요청인지를 판단하고, 동일한 요청이라면 백엔드 서버에 요청을 보내지 않고 캐시한 요청에 대한 응답을 유저에게 회신한다. 
- 웹 캐시는 HTTP요청 중 몇 가지 요소를 기준으로 동일한 요청인지를 판단한다. (보통 Host 헤더나 요청 패스등이다.)
- 어떤 HTTP 요청이 웹 캐시의 판단 기준에 매칭되는 요청이라면 "keyed"라고 하고, 그 반대라면 "unkeyed"라고 한다. 

# 랩 개요
- 랩 서버에는 HTTP요청의 "unkeyed" 헤더를 핸들링하는 부분이 취약하기 때문에 웹 캐시 포이즈닝 공격이 가능하다. 
- 일반 유저가 정기적으로 랩 사이트를 방문한다. 
- HTTP응답을 캐시시켜, 일반 유저에게 alert(document.cookie) 코드를 실행시키면 랩이 풀린다. 
- 힌트: 이 랩은 `X-Forwarded-Host` 헤더를 지원한다. 

```
This lab is vulnerable to web cache poisoning because it handles input from an unkeyed header in an unsafe way. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes alert(document.cookie) in the visitor's browser.
Hint
This lab supports the X-Forwarded-Host header.
```

# 풀이 
1. `GET /` 요청에 `X-Forwarded-Host` 헤더를 추가해서 보내본다. 그러면 응답 페이지에 이 헤더에 지정한 값(test.com)이 script 엘레먼트의 도메인으로 출력되는 것을 볼 수 있다. 이를 활용하면 유저에게 자신이 원하는 javascript를 실행시킬 수 있겠다.

```html
<script type="text/javascript" src="//test.com/resources/js/tracking.js">
```

![X-Forwarded-Host 테스트](/images/burp-academy-wcp-1-1.png)

2. exploit서버의 `/resources/js/tracking.js` 패스로 요청이 오면 `alert(document.cookie)`가 실행되도록 구성한다. 

![exploit서버 구성](/images/burp-academy-wcp-1-2.png)

3. `GET /` 요청에 `X-Forwarded-Host` 헤더의 값을 exploit 서버의 도메인으로 설정해서 보낸다. HTTP 응답을 통해 이 요청이 기존에 캐싱되지 않았던 요청 (unkeyed) 이었던 것을 알 수 있다. 이제 이 요청은 캐싱되었을 것이다. 

![웹 캐시 포이즈닝 시도](/images/burp-academy-wcp-1-3.png)

4. 웹 브라우저로 랩 사이트에 접속하면 자바스크립트 alert창이 뜨고 문제 풀이에 성공해다는 메세지가 출력된다. 

![풀이 성공](/images/burp-academy-wcp-1-success.png)
