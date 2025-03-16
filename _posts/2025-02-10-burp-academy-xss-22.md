---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS into a JavaScript string with angle brackets HTML encoded"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-02-10 21:55:00 +0900
---

# 개요
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/contexts#xss-into-javascript
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded
- 난이도: APPRENTICE (쉬움)


# 취약점 개요 (Breaking out of a JavaScript string)
XSS 컨텍스트가 인용된 문자열 리터럴 내부에 있는 경우, 종종 문자열에서 벗어나 JavaScript를 직접 실행할 수 있다. XSS 컨텍스트 다음에 스크립트를 복구하는 것이 필수적이다. 거기에 구문 오류가 있으면 전체 스크립트가 실행되지 않기 때문이다.

문자열 리터럴을 벗어나는 데 유용한 방법은 다음과 같다.

```
'-alert(document.domain)-'
';alert(document.domain)//
```


# 랩 개요
- 이 랩에는 꺽쇠(<>)를 인코드하는 검색 쿼리 추적기능에 반사형 XSS 취약점이 있다. 
- XSS는 Javascript 문자열 내에서 발생한다. 
- 랩을 퓰려면 Javascript 문자열을 부수는 XSS를 수행해서 alert함수를 호출하면 된다. 


```
This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality where angle brackets are encoded. The reflection occurs inside a JavaScript string. To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the alert function.
```

# 도전

1. 랩을 살펴본다. `"/><script>alert(1);</script>`로 검색해봤다. 이번에는 꺽쇠가 HTML인코딩된 상태로 들어간다! 

![](/images/burp-academy-xss-22-1.png)


2. 작음따옴표를 테스트해본다. `';`를 검색해본다. 그러면 HTML인코딩된(혹은 이스케이프된) 상태가 아니라 그대로 들어가는 것을 알 수 있다. Javascript의 문자열을 벗어날 수 있게 되었다. 

![](/images/burp-academy-xss-22-2.png)

3. 다음 페이로드를 검색어로 입력해서 검색해본다. 

```js
';alert(1);//
```

그러면 다음과 같이 Javascript내에 삽입되고 얼럿창이 뜨는 것을 볼 수 있다. 

![](/images/burp-academy-xss-22-4.png)

![](/images/burp-academy-xss-22-3.png)


4. 랩이 풀렸다. 

![](/images/burp-academy-xss-22-success.png)