---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-03-05 05:55:00 +0900
---

# 개요
- HTML 태그의 속성에서 발생하는 XSS 취약점 문제이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/
- 랩 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped
- 난이도: PRACTITIONER (보통)

# 취약점 설명 (XSS in JavaScript template literals)
JavaScript template literal은 내장된 JavaScript 표현식을 허용하는 문자열 표기법이다. 내장된 표현식은 평가되고 일반적으로 주변 텍스트와 이어진다. 템플릿 표기법은 일반 따옴표 대신 백틱(\`)으로 캡슐화되고 내장된 표현식은 `${...}`구문을 사용하여 식별된다.

예를 들어, 다음 스크립트는 사용자의 이름을 포함하는 환영 메시지를 출력한다.

```js
document.getElementById('message').innerText = `Welcome, ${user.displayName}.`;
```

XSS 컨텍스트가 JavaScript 템플릿안에 있는 경우 리터럴을 종료할 필요가 없다. 대신, `${...}`리터럴이 처리될 때 실행될 JavaScript를 사용하기만 하면 된다. 예를 들어, XSS 컨텍스트가 다음과 같은 경우:

```html
<script>
...
var input = `controllable data here`;
...
</script>
```

템플릿 리터럴을 종료하지 않고도 다음 페이로드를 사용하여 JavaScript를 실행할 수 있다.

```js
${alert(document.domain)}
```


# 랩 개요 
- 이 사이트의 블로그 글 검색 기능에 반사형 XSS취약점이 존재한다. 
- 반사는 Javascript 템플릿안에서 일어난다. 이 템플릿안에서는 앵글브라켓(꺽쇠, `<>`)과, 싱글 쿼트(작은 따옴표, `'`), 더블 쿼트(쌍 따옴표, `"`)는 HTML 인코딩되고, 백틱(`\``)은 이스케이프된다. 
- 랩을 풀려면 XSS공격을 수행해서 템플릿 문자열안에서 alert함수가 실행되도록 한다. 

```
This lab contains a reflected cross-site scripting vulnerability in the search blog functionality. The reflection occurs inside a template string with angle brackets, single, and double quotes HTML encoded, and backticks escaped. To solve this lab, perform a cross-site scripting attack that calls the alert function inside the template string.
```

# 풀이 
1. 랩을 살펴본다. 블로그의 글 검색기능이 존재한다. 

![](/images/burp-academy-xss-25-2.png)


2. 여기에 페이로드 `"/><script>alert(1);</script>`를 입력해서 검색해본다. 검색 결과 HTML페이지는 다음과 같았다. 입력값이 Javascript의 템플릿안에 삽입되는 것을 알 수 있다. 그리고 특수문자가 인코딩된 것을 알 수 있다. 

![](/images/burp-academy-xss-25-1.png)

3. 검색어로 페이로드 `${alert(document.domain)}`를 입력해본다. 

4. 그러면 화면에 alert창이 뜬다. 그리고 HTML페이지를 보면 다음과 같이 그대로 페이로드가 삽입된 것을 볼 수 있다. 템플릿에서 사용가능한 표현식이 평가(Evaluate)되었기 때문에 alert창이 발동되었다. 

![](/images/burp-academy-xss-25-3.png)

5. 랩이 풀렸다. 

![](/images/burp-academy-xss-25-success.png)