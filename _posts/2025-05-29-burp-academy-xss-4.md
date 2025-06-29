---
layout: post
title: "Burp Academy-XSS 취약점: DOM XSS in innerHTML sink using source location.search"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-05-07 21:55:00 +0900
---

# 개요
- Dom기반 XSS 취약점 랩이다.
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink
- 취약점 설명: https://portswigger.net/web-security/cross-site-scripting/dom-based
- 난이도: APPRENTICE (쉬움)

# 취약점 설명

`innerHTML` 싱크는 최신 브라우저에서 `script` 요소를 허용하지 않으며, `svg onload` 이벤트도 발생시키지 않는다. 이는 `img` 또는 `iframe` 과 같은 다른 요소를 사용해야 한다는 것을 의미한다. `onload` 및 `onerror`와 같은 이벤트 핸들러를 이러한 요소와 함께 사용할 수 있습니다. 예:

```js
element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'
```

# 랩 개요
- 이 랩은 블로그 검색 기능에 DOM 기반 크로스 사이트 스크립팅 취약점을 포함하고 있다.
- 이 취약점은 `location.search` 로부터 데이터를 얻어 `innerHTML` 할당을 사용하여 `div`의 HTML 컨텐츠를 변경한다. 
- 이 랩을 풀려면 `alert` 함수를 호출하는 XSS 공격을 수행하라.

```
This lab contains a DOM-based cross-site scripting vulnerability in the search blog functionality. It uses an innerHTML assignment, which changes the HTML contents of a div element, using data from location.search.

To solve this lab, perform a cross-site scripting attack that calls the alert function.
```


# 풀이

1. 일단 취약점이 있어보이는 곳을 찾는다. 검색을 해보면 응답페이지에서 다음 코드를 볼 수 있다. 검색한 값이 그대로 `searchMessage` 요소에 `innerHTML`을 통해 삽입인되는 것을 알 수 있다. 

```html
<span id="searchMessage"></span><span>'</span></h1>
<script>
    function doSearchQuery(query) {
        document.getElementById('searchMessage').innerHTML = query;
    }
    var query = (new URLSearchParams(window.location.search)).get('search');
    if(query) {
        doSearchQuery(query);
    }
</script>
```

![](/images/burp-academy-xss-4-1.png)

2. 페이로드를 생각해본다. 취약점 설명에 따르면 `img`를 사용하면 좋을 것 같다. 다음 페이로드를 검색창에 넣어보자.

```html
<img src=1 onerror=alert(document.domain)>
```


3. 그러면 페이로드가 그대로 삽입되고 그 결과로 얼럿창이 뜨는 것을 확인할 수 있다. 

![](/images/burp-academy-xss-4-2.png)

4. 랩이 풀렸다. 

![](/images/burp-academy-xss-4-success.png)