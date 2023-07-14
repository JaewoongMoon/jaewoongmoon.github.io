---
layout: post
title: "Dom-based XSS 정리"
categories: [웹 취약점, XSS, Dom-based XSS]
tags: [웹 취약점, XSS, Dom-based XSS]
toc: true
last_modified_at: 2023-07-15 17:02:00 +0900
---


# 개요
- Dom-based XSS 를 검사하는 방법을 정리한다. 
- 특히 특정 jquery 라이브러리를 사용하고 있는 경우에 검사하는 방법을 정리한다. 

# 사용중인 jquery 라이브러리 확인
브라우저 콘솔에서 다음 명령을 치면 버전을 확인할 수 있다. 

```
console.log(jQuery().jquery);
```

jquery 라이브러리의 버전 히스토리는 다음 링크에서 확인가능하다. 

https://en.wikipedia.org/wiki/JQuery

# 직접 구성해 본다. 
다음 링크에서 HTML 페이지에 import 가능한 jquery CDN 경로를 얻어올 수 있다. 

https://releases.jquery.com/jquery/


1. 검증할 HTML 페이지 작성
2. 로컬 서버로 구동
3. 테스트 

# 어떤 페이로드로 Dom-XSS가 일어나는 보고 싶을 때 참고 
- https://jsfiddle.net/TwBaS/
- https://stackoverflow.com/questions/11169894/can-malicious-javascript-code-be-injected-through

# 참고 

jquery 를 사용하는 경우, 유저로부터의 입력이 다음 함수들로 전달되면 위험하다고 판단할 수 있다. 

```
add()
after()
append()
animate()
insertAfter()
insertBefore()
before()
html()
prepend()
replaceAll()
replaceWith()
wrap()
wrapInner()
wrapAll()
has()
constructor()
init()
index()
jQuery.parseHTML()
$.parseHTML()
```


- https://portswigger.net/web-security/cross-site-scripting/dom-based