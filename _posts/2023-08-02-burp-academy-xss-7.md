---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS into attribute with angle brackets HTML-encoded"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-06-20 05:55:00 +0900
---

# 개요
- Reflected 타입의 XSS 취약점 랩이다. 사용자의 입력이 HTML태그의 속성(Attribute)에 들어가는 패턴이다. 
- 랩 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded
- 취약점 설명: https://portswigger.net/web-security/cross-site-scripting/contexts
- 난이도: APPRENTICE (쉬움)

# HTML 태그 속성의 XSS
XSS 컨텍스트(사용자의 입력이 삽입되는 부분)가 HTML 태그 속성 값에 있을 때, 속성 값을 종료하고 태그를 닫은 후 새 태그를 삽입할 수 있는 경우가 있다. 예를 들면 다음과 같은 경우다. 

```js
"><script>alert(document.domain)</script>
```

이런 상황에서는 일반적으로 꺾쇠괄호가 차단되거나 인코딩되어 입력 내용이 태그 밖으로 나갈 수 없다. 꺾쇠괄호는 사용하지 못하더라도, 쌍따옴표를 사용가능하다면 속성 값을 종료할 수 있다. 속성 값을 종료할 수 있다면 이벤트 핸들러와 같은 스크립팅 가능한 컨텍스트를 생성하는 새 속성을 추가할 수 있. 예를 들면 다음과 같다.

```js
" autofocus onfocus=alert(document.domain) x="
```

위 페이로드는 HTML요소가 포커스를 받을 때 JavaScript를 실행하는 `onfocus` 이벤트를 생성하고, 사용자 상호 작용 없이 `onfocus` 이벤트를 자동으로 트리거하는  `autofocus` 속성을 추가한다. 마지막으로, `x="`를 추가하여 뒤따르는 마크업이 정상적으로 처리되도록 한다. 


# 문제
- 이 랩은 블로그의 검색 기능에 Reflected XSS취약점이 존재한다. 한편, 꺽쇠기호(angle bracket)가 HTML인코드 된다. 
- 랩을 풀려면 XSS페이로드를 보내서 alert 함수를 실행시키면 문제가 풀린다. 

```
This lab contains a reflected cross-site scripting vulnerability in the search blog functionality where angle brackets are HTML-encoded. To solve this lab, perform a cross-site scripting attack that injects an attribute and calls the alert function.
```

# 풀이 
1. 검색화면에서 다음 XSS 페이로드를 테스트해본다.

```js
" onfocus=javascript:alert(1);
```

2. 그러면 쌍따옴표 (더블 쿼테이션,")삽입이 가능한 것을 알 수 있다. 

![싱크발견](/images/burp-academy-xss-7-sink.png)

3. 그런데 이 상태에서는 다음과 같은 자바스크립트 에러가 발생한다. 

![Chrome에서 발생](/images/burp-academy-xss-7-1.png)

4. 다음과 같이 마지막에 쌍따움표를 하나 더 붙여주어야 한다. 

```js
" onfocus=javascript:alert(1);"
```

5. 위의 페이로드로 검색을 수행하면 alert창이 호출되고 랩이 풀린다. 

![성공](/images/burp-academy-xss-7-success.png)