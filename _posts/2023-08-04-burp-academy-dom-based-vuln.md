---
layout: post
title: "Burp Academy-Dom 관련 취약점 설명"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Dom 관련 취약점]
toc: true
last_modified_at: 2023-08-04 05:55:00 +0900
---

# 개요 
- Burp Academy의 Dom-based 취약점 설명을 읽고 이해한 것을 정리하는 페이지다. 
- https://portswigger.net/web-security/dom-based
- https://portswigger.net/web-security/dom-based/controlling-the-web-message-source

# Taint-flow vulnerabilities
두 가지 개념을 확실히 이해할 필요가 있다. 

## Sources
- Source란 공격자가 컨트롤가능한 데이터를 받아들이는 자바스크립트 속성(프로퍼티)이다. 
- 예를 들면, `location.search`와 같은 속성이다. 
- 공격자가 컨트롤가능한 속성은 모두 Source로 볼 수 있다. 
- 이는 `document.referrer`나 `document.cookie`, 웹 메세지를 포함한다. 

## Sinks 
- Sink(싱크)란 공격자가 컨트롤할 수 있는 데이터를 처리하는 과정에서 위험할 수 있는 (potentially dangerous) 자바스크립트 함수나 DOM 오브젝트이다. 
- 예를들면 `eval()`함수나 `document.body.innerHTML`등이다. 

기본적으로, 웹 사이트가 Source에서 Sink로 데이터를 전달하면 Dom-based 취약점이 일어날 수 있다. 

## 알려진 source들 
다음과 같은 것들이 일반적인 Source들이다. 

```
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
document.cookie
document.referrer
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
Database
```

## 알려진 sink들
유저가 컨트롤 가능한 입력이 다음 함수들의 파라메터로 쓰이면 sink라고 볼 수 있다. 다음 자바 스크립트 함수나 코드가 대표적인 sink이다. 

```
document.write()
document.writeln()
document.domain
element.innerHTML
element.outerHTML
element.insertAdjacentHTML
element.onevent
```

다음 jQuery함수들도 알려진 sink이다. 

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

