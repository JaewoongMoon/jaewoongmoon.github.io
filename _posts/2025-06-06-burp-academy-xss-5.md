---
layout: post
title: "Burp Academy-XSS 취약점: DOM XSS in jQuery anchor href attribute sink using location.search source"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-06-06 21:55:00 +0900
---

# 개요
- Dom기반 XSS 취약점 랩이다.
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink
- 취약점 설명: https://portswigger.net/web-security/cross-site-scripting/dom-based
- 난이도: APPRENTICE (쉬움)


# 취약점 설명: 서드파티 종속성의 소스 및 싱크
최신 웹 애플리케이션은 일반적으로 여러 서드파티 라이브러리와 프레임워크를 사용하여 구축되며, 이러한 라이브러리와 프레임워크는 개발자에게 추가 기능과 성능을 제공한다. 이러한 라이브러리와 프레임워크 중 일부는 DOM XSS의 잠재적인 소스 및 싱크가 될 수 있다는 점을 기억하는 것이 중요하다. 

## jQuery의 DOM XSS
jQuery와 같은 JavaScript 라이브러리를 사용하는 경우, 페이지의 DOM 요소를 변경할 수 있는 싱크(sink)를 주의 깊게 살펴보아야 한다. 예를 들어, jQuery의 `attr()`함수는 DOM 요소의 속성을 변경할 수 있다. URL과 같은 사용자가 제어하는 ​​소스에서 데이터를 읽어 함수에 전달하는 경우, 전달되는 값을 조작하여 XSS를 유발할 수 있다. 예를 들어, URL의 데이터를 사용하여 앵커 요소의 `href` 속성을 변경하는 JavaScript 코드는 다음과 같다. 

```js
$(function() {
	$('#backLink').attr("href",(new URLSearchParams(window.location.search)).get('returnUrl'));
});
```

다음과 같이 URL을 수정하여 `location.search` 소스에 악성 JavaScript URL을 포함하도록 하면 이 취약점을 exploit할 수 있다. 페이지의 JavaScript가 이 악성 URL을 백 링크의 `href` 에 적용한 후 , 백 링크를 클릭하면 코드가 실행된다. 

```js
?returnUrl=javascript:alert(document.domain)
```

# 랩 설명
- 이 랩은 피드백 제출 페이지에 DOM 기반 크로스 사이트 스크립팅 취약점을 포함하고 있다.
- 이 취약점은 jQuery의 `$`셀렉터 함수를 이용해 앵커 엘레먼트를 찾은 후, 앵커 태그의 href 속성의 값을 `location.search`에서 얻은 데이터로 바꾼다.
- 이 랩을 풀려면 "back"링크를 클릭했을 때 `alert(document.cookie)`가 동작하도록 하라. 

```
This lab contains a DOM-based cross-site scripting vulnerability in the submit feedback page. It uses the jQuery library's $ selector function to find an anchor element, and changes its href attribute using data from location.search.

To solve this lab, make the "back" link alert document.cookie.
```


# 도전
1. 일단 취약점이 있는 곳을 찾는다. 랩의 상단을 보면 Submit feedback이라는 링크가 있다. 

![](/images/burp-academy-xss-5-1.png)

2. 링크를 클릭해보면 URL패스가 `/feedback?returnPath=/` 인 것을 알 수 있다. returnPath에 페이로드를 지정하면 공격이 가능해보인다. 

3. 웹 페이지 소스코드를 살펴본다. 그러면 다음과 같은 코드가 있는 것을 알 수 있다. window.location.search 의 returnPath의 값이 백버튼이 href 속성에 바로 지정되도록 되어 있다. XSS가 가능하다. 

```html
<script>
    $(function() {
        $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
    });
</script>
```

![](/images/burp-academy-xss-5-2.png)

4. returnPath에 페이로드 `javascript:alert(document.cookie)`를 설정해서 페이지에 접속해본다. 전체 URL은 `https://{LAB-ID}.web-security-academy.net//feedback?returnPath=javascript:alert(document.cookie)`과 같이 된다. 

5. 잠시 기다리면 랩이 풀린다. 

![](/images/burp-academy-xss-5-success.png)