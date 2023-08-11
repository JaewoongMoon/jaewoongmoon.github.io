---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS into attribute with angle brackets HTML-encoded"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2023-08-04 05:55:00 +0900
---

# 개요
- Reflected 타입의 XSS 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded
- 난이도: APPRENTICE (쉬움)

# 문제
- 이 사이트의 블로그의 검색 기능에 Reflected XSS취약점이 존재한다. 
- 구체적으로는 angle bracket(<> 기호)이 HTML인코드 되는 부분이다. 
- XSS페이로드를 보내서 alert 함수를 실행시키면 문제가 풀린다. 

```
This lab contains a reflected cross-site scripting vulnerability in the search blog functionality where angle brackets are HTML-encoded. To solve this lab, perform a cross-site scripting attack that injects an attribute and calls the alert function.
```

# 풀이 
## 예상 
- 어느정도는 XSS 대책이 되어 있지만 일부 허점이 있을 것 같다. 
- 문제설명에서 HTML 인코딩 부분에서 취약점이 있다고 했으니 이 방향으로 생각해보자. 
- XSS Cheatsheet에서 HTML 인코딩과 관련된 부분을 찾아보자. 

## 도전 
검색화면에서 XX페이로드를 테스트해본다.

```
" onfocus=javascript:alert(1);
```

그러면 쌍따옴표 (더블 쿼테이션,")삽입이 가능한 것을 알 수 있다. 

![싱크발견](/images/burp-academy-xss-6-sink.png)

그런데 `" onfocus=javascript:alert(1);`를 삽입한 상태에서는 크롬에서 다음과 같은 자바스크립트 에러가 발생한다. 

![Chrome에서 발생](/images/burp-academy-xss-6-1.png)

다음과 같이 마지막에 쌍따움표를 하나 더 붙여주어야 제대로 동작했다. 

```
" onfocus=javascript:alert(1);"
```

alert창이 호출되면 성공했다는 팝업이 뜬다. 

![성공](/images/burp-academy-xss-6-success.png)