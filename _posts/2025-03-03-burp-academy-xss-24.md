---
layout: post
title: "Burp Academy-XSS 취약점: Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-03-03 05:55:00 +0900
---

# 개요
- HTML 태그의 속성에서 발생하는 XSS 취약점 문제이다. 
- 취약점 설명 주소:  https://portswigger.net/web-security/cross-site-scripting/contexts/
- 랩 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped
- 난이도: PRACTITIONER (보통)

# 취약점 설명 (HTML 인코딩 활용하기 Making use of HTML-encoding)
XSS 를 삽입가능한 곳이 이벤트 핸들러와 같은 태그 속성 내의 기존 JavaScript의 내부인 경우 HTML 인코딩을 사용하여 일부 입력 필터를 우회할 수 있는 경우가 있다. 

브라우저가 HTML 태그와 속성을 구문 분석할 때, 태그 속성 값을 처리하기 전에 HTML 디코딩을 수행한다. 서버 측 애플리케이션이 XSS공격에 사용되는 특정 문자를 차단하거나 삭제하는 경우 해당 문자를 HTML 인코딩하여 입력 검증을 우회할 수 있는 경우가 있다.

예를 들어 XSS 컨텍스트가 다음과 같은 경우:

```html
<a href="#" onclick="... var input='controllable data here'; ...">
```

애플리케이션이 작은따옴표 문자를 차단하거나 이스케이프하는 경우 다음 페이로드를 사용하여 JavaScript 문자열을 분리하여 스크립트를 실행할 수 있다.


```html
&apos;-alert(document.domain)-&apos;
```

`&apos;` 는 작은따옴표나 아포스트로피를 나타내는 HTML 엔터티다. 브라우저가 JavaScript를 해석하기 전에 onclick 속성의 값을 HTML 디코딩하기 때문에 엔터티는 작은따옴표로 디코딩되고, 작은 따옴표는 문자열 구분 기호가 되므로 공격이 성공한다.


# 랩 개요 
- 이 사이트의 블로그의 댓글 기능에 Stored XSS취약점이 존재한다. 
- 랩을 풀려면 댓글의 작성자를 클릭하면 alert함수가 실행되도록 하면 된다.  

```
This lab contains a stored cross-site scripting vulnerability in the comment functionality.

To solve this lab, submit a comment that calls the alert function when the comment author name is clicked.
```

# 풀이 
1. 일단 살펴본다. 댓글을 작성하고 나면 다음과 같이 WebSite 항목에 입력했던 값이 onclick이벤트의 Javascript 코드에 삽입되는 것을 알 수 있다. 

![](/images/burp-academy-xss-24-1.png)

2. WebSite에 페이로드 `&apos;-alert(document.domain)-&apos;`를 적어본다. 입력 값이 URL형식인지 검사하기 때문에 앞에 https://exmample.com 과 같은 식으로 URL같은 문자열을 붙여서 댓글을 작성해본다. 

![](/images/burp-academy-xss-24-2.png)

3. 댓글을 저장한 결과는 다음과 같다. HTML페이지상에서는 페이로드가 그대로 들어간 것을 알 수 있다. 

![](/images/burp-academy-xss-24-3.png)

4. HTML 페이지를 웹 브라우저의 개발자 도구로 보면 다음과 같이 보인다. `&apos;`가 HTML디코딩되어서 보인다! 😯 작은 따옴표가 부활했다. 작성자를 클릭하면 alert창이 뜨는 걸 확인할 수 있다. 

![](/images/burp-academy-xss-24-4.png)

5. 랩이 풀렸다. 

![](/images/burp-academy-xss-24-success.png)