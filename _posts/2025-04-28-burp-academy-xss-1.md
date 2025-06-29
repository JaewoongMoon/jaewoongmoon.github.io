---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS into HTML context with nothing encoded"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-04-28 21:55:00 +0900
---

# 개요
- 반사형 타입의 XSS 취약점 랩이다.
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded
- 취약점 설명: https://portswigger.net/web-security/cross-site-scripting/reflected
- 난이도: APPRENTICE (쉬움)


# 랩 개요
- 이 랩은 검색기능에 간단히 실행가능한 반사형 XSS취약점이 있다. 
- 랩을 풀려면 XSS공격을 수행해서 alert함수를 실행시킨다. 

```
This lab contains a simple reflected cross-site scripting vulnerability in the search functionality.

To solve the lab, perform a cross-site scripting attack that calls the alert function.
```


# 도전
1. 검색창에 페이로드 `<script>alert(1);</script>`를 입력하고 Search 버튼을 누른다. 

![](/images/burp-academy-xss-1-1.png)

2. 페이로드가 전혀 이스케이프 처리 되지 않고 그대로 HTML페이지에 출력된다. alert창이 뜬다.

![](/images/burp-academy-xss-1-2.png)

3. 랩이 풀렸다. 

![](/images/burp-academy-xss-1-success.png)