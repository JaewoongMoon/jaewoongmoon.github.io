---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS into a JavaScript string with single quote and backslash escaped"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-02-06 21:55:00 +0900
---

# 개요
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/contexts#xss-into-javascript
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped
- 난이도: PRACTITIONER (보통)


# 취약점 개요 (XSS into Javascript)

## 기존 스크립트 종료 
가장 간단한 경우, 기존 JavaScript를 둘러싼 스크립트 태그를 닫고 새로운 HTML 태그를 삽입할 수 있다. 예를 들어, XSS 컨텍스트가 다음과 같은 경우다:

```html
<script>
...
var input = 'controllable data here';
...
</script>
```

이럴 경우 다음 페이로드를 사용하여 기존 JavaScript에서 탈출해서 새로운 JavaScript를 실행할 수 있다.

```html
</script><img src=1 onerror=alert(document.domain)>
```

이게 작동하는 이유는 브라우저가 **먼저 HTML 구문 분석을 수행하여 스크립트 블록을 포함한 페이지 요소를 식별하고** 나중에 JavaScript 구문 분석을 수행하여 스크립트를 이해하고 실행하기 때문이다. 위의 페이로드는 원래 스크립트 블록을 닫고, 종료되지 않은 문자열 리터럴을 남겨둔다. 하지만 후속 스크립트가 정상적인 방식으로 구문 분석되고 실행되는 것을 막지는 못한다.


# 랩 개요
- 이 랩에는 검색 쿼리 추적기능에 반사형 XSS 취약점이 있다. 
- XSS는 작은 따옴표(싱글 쿼트)와 역슬래시를 이스케이프한 Javascript 문자열 내에서 발생한다. 
- 랩을 퓰려면 Javascript 문자열을 부수는 XSS를 수행해서 alert함수를 호출하면 된다. 


```
This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality. The reflection occurs inside a JavaScript string with single quotes and backslashes escaped.

To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the alert function.
```

# 도전

1. 랩을 살펴본다. 상품 검색 기능이 있다. holiday라는 검색어로 검색해보았다. 

![](/images/burp-academy-xss-21-1.png)

2. 이 때의 HTML 페이지를 살펴보면 다음과 같다. Javascript 내의 문자열에 검색어가 들어가 있다. 여기를 공략하면 될 것 같다. 

![](/images/burp-academy-xss-21-2.png) 

3. XSS 테스트용 페이로드를 붙여서 검색해본다. `holiday'"/>` 로 검색해보았다. 결과는 다음과 같다. 
 
![](/images/burp-academy-xss-21-3.png)

이를 통해 다음을 알 수 있다. 

1) 작은 따옴표는 이스케이프 처리된다. 
2) 큰 따옴표는 이스케이프 처리되지 않는다.
3) 꺽쇠가 이스케이프 처리되지 않는다. 

4. 페이로드를 좀 더 생각해본다. 꺽쇠가 이스케이프 처리되지 않으므로 닫는 script 태그를 쓰면 될 것 같다. 

5. 다음 페이로드를 시험해본다. 

```html
<script>alert(1);</script>
```

그러자 다음과 같이 Javascript 코드가 삐져나온 것을 볼 수 있다! 🍕

![](/images/burp-academy-xss-21-4.png)

페이지의 코드는 다음과 같이 되어 있다. 닫는 script 태그가 먹힌 것이다. 

![](/images/burp-academy-xss-21-5.png)

6. 닫는 script 태그를 사용할 수 있으므로 한번 script 태그를 닫고 새로운 script 태그를 삽입하면 XSS가 될 것 같다. 다음을 사용해본다. 

```html
</script><script>alert(1);
```

결과 페이지에서 alert창이 뜨지 않는다. 원인을 조사하기 위해서 웹 브라우저의 개발자 도구에서 콘솔창을 보면 에러메세지를 확인할 수 있다. 문법 에러가 발생했다. 

![](/images/burp-academy-xss-21-6.png)

HTML페이지 코드를 보면 다음과 같다. alert(1); 뒤에 붙어있는 '; 가 원인인 것 같다. 

![](/images/burp-academy-xss-21-7.png)


7. 페이로드를 다음과 같이 수정해서 다시 한번 시도해본다. 

```html
</script><script>alert(1);//
```

그러면 alert창이 뜨는 것을 볼 수 있다. 랩이 풀렸다. 

![](/images/burp-academy-xss-21-success.png)