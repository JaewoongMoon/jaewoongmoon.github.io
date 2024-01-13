---
layout: post
title: "Burp Academy-웹 캐시 포이즈닝 관련 취약점: Web cache poisoning with an unkeyed cookie"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Web Cache Poisoning]
toc: true
last_modified_at: 2023-12-25 09:50:00 +0900
---

# 개요
- 웹 캐시 포이즈닝 취약점을 이용한 문제이다. 
- 문제 주소: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-cookie
- 취약점 설명페이지: https://portswigger.net/web-security/web-cache-poisoning
- 난이도: PRACTITIONER (보통)

# 웹 캐시 개념 / 용어
- 웹 캐시에는 캐시 키(Cache Key)라는 개념이 있다. 유저로부터의 요청이 자신이 캐시하고 있는 요청과 동일한 요청인지를 판단하고, 동일한 요청이라면 백엔드 서버에 요청을 보내지 않고 캐시한 요청에 대한 응답을 유저에게 회신한다. 
- 웹 캐시는 HTTP요청 중 몇 가지 요소를 기준으로 동일한 요청인지를 판단한다. (보통 Host 헤더나 요청 패스등이다.)
- 어떤 HTTP 요청이 웹 캐시의 판단 기준에 매칭되는 요청이라면 "keyed"라고 하고, 그 반대라면 "unkeyed"라고 한다. 

# 랩 개요
- 랩 서버의 구현상 HTTP요청의 쿠키가 캐시 키에 포함되지 않기 때문에 웹 캐시 포이즈닝 공격이 가능하다. 
- 일반 유저가 정기적으로 랩 사이트를 방문한다. 
- HTTP응답을 캐시시켜, 일반 유저에게 alert(document.cookie) 코드를 실행시키면 랩이 풀린다. 

```
This lab is vulnerable to web cache poisoning because cookies aren't included in the cache key. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes alert(1) in the visitor's browser.
```

# 풀이 
1. 이 랩에는 exploit 서버가 주어지지 않았다. 

2. HTTP 요청은 다음과 같이 생겼다. 쿠키중에 `fehost`라는 쿠키이 있고 이 값이 HTTP응답에 그대로 나타난다. 테스트해보면 특수문자도 그대로 출력되는 것을 볼 수 있다. Javascript를 삽입하는 것이 가능하다. 그리고 웹 캐시의 Age가 30을 넘으면 새로운 페이지가 캐싱되는 것도 확인했다. 

![HTTP 요청 관찰](/images/burp-academy-wcp-2-1.png)

3. `alert(document.cookie)`가 동작하도록 페이로드를 궁리한다. 몇 번 테스트해서 `prod-cache-02"}%3balert(document.cookie)%3btest={"test":"xxx` 가 성공적으로 동작하는 것을 확인했다. ✨ 랩 서버는 쿠키를 캐시 키에 포함하지 않기 때문에 일반 사용자들이 `GET /` 로 접근하면 XSS 페이로드가 포함된 페이지가 회신될 것이다. (쿠키를 캐시 키에 포함하면 XSS페이로드가 포함된 동일한 쿠키 값을 보내지 않는 이상 XSS페이로드가 포함된 페이지가 회신되지 않는다.)

![자바스크립트 페이로드 삽입](/images/burp-academy-wcp-2-2.png)

4. 조금 기다리면 문제 풀이에 성공했다는 메세지가 출력된다. 

![풀이 성공](/images/burp-academy-wcp-2-success.png)