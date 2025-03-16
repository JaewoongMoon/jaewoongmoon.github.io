---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-02-12 21:55:00 +0900
---

# 개요
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/contexts#xss-into-javascript
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped
- 난이도: PRACTITIONER (보통)


# 취약점 개요 (Breaking out of a JavaScript string)
일부 애플리케이션은 작은 따옴표를 백슬래시로 이스케이프하여 JavaScript 문자열에서 입력이 끊어지는 것을 방지하려고 시도한다. 문자 앞에 백슬래시를 붙이면 JavaScript 파서에 해당 문자가 특수 문자가 아니라 문자 그대로 해석되어야 함을 알려준다. 이런 상황에서 **애플리케이션은 종종 백슬래시 문자 자체를 이스케이프하지 못하는 실수를 한다.** 이를 통해 공격자는 자신의 백슬래시 문자를 사용하여 애플리케이션에서 추가한 백슬래시를 무효화할 수 있다.

예를 들어, 입력이 다음과 같다고 가정해 보자.

```
';alert(document.domain)//
```

이는 다음으로 변환된다. 

```
\';alert(document.domain)//
```

만약 다음과 같은 페이로드를 사용해보자. 

```
\';alert(document.domain)//
```

이는 다음으로 변환된다. 

```
\\';alert(document.domain)//
```

여기서 첫 번째 백슬래시는 두 번째 백슬래시가 특수 문자가 아닌 문자 그대로 해석된다는 것을 의미한다. 따라서 작은 따옴표는 이제 문자열 종료자로 해석되므로 공격이 성공합니다.


# 랩 개요
- 이 랩에는 꺽쇠(<>)를 HTML 인코드하고,  작은 따옴표(')를 이스케이프하는 검색 쿼리 추적기능에 반사형 XSS 취약점이 있다. 
- 랩을 퓰려면 Javascript 문자열을 부수는 XSS를 수행해서 alert함수를 호출하면 된다. 


```
This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality where angle brackets and double are HTML encoded and single quotes are escaped.

To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the alert function.


```

# 도전

1. 랩을 살펴본다. `\'test`로 검색해본다. 

2. 그러면 다음과 같이 역슬래시가 이스케이프 되어 (`\\`가 되어) 뒤에 있는 작은따옴표가 문자열 종료자로 처리된 것을 볼 수 있다. Javascript 문자열을 빠져나오는데 성공했다. 

![](/images/burp-academy-xss-23-1.png)

![](/images/burp-academy-xss-23-2.png)

3. 그렇다면 다음 페이로드를 사용하면 Javascript함수가 실행될 것 이다. 

```js
\';alert(1);//
```

이 페이로드가 삽입되면 다음과 같은 형태가 될 것이기 때문이다. 

```js
var searchTerms = '\\';alert(1);//';
```

4. 테스트해본다. 다음과 같이 삽입되고 alert창이 뜨는 것을 알 수 있다. 

![](/images/burp-academy-xss-23-3.png)


5. 랩이 풀렸다. 

![](/images/burp-academy-xss-23-success.png)
