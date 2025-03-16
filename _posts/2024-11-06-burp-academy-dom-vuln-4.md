---
layout: post
title: "Burp Academy-Dom 관련 취약점: DOM-based open redirection"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Dom 관련 취약점, XSS]
toc: true
last_modified_at: 2024-11-06 09:33:00 +0900
---

# 개요
- Dom based 타입의 XSS 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection
- 취약점 설명페이지: https://portswigger.net/web-security/dom-based/open-redirection
- 난이도: PRACTITIONER (보통)


# Open Redirection 취약점 개요
- Open Redirection 은 피싱 공격에 이용될 가능성이 있는 취약점이다. 
- CVE 데이터베이스를 찾아보면 Open Redirection의 CVSS 스코어는 Medium 인 경우가 많았다. 
- DOM-based Open Redirection 은 공격자가 컨트롤 가능한 데이터가 크로스 도메인을 탐색할 수 있는 sink로 전달될 때 일어난다. 예를 들면, 다음 코드는 `location.hash` 속성을 안전하게 핸들링하고 있지 않기 때문에 취약하다. 

```js
let url = /https?:\/\/.+/.exec(location.hash);
if (url) {
  location = url[0];
}
```

## DOM-based Open Redirection 을 일으킬 수 있다고 알려진 sink

다음이 DOM-based Open Redirection 을 일으킬 수 있다고 알려진 sink 들이다. 

```js
location
location.host
location.hostname
location.href
location.pathname
location.search
location.protocol
location.assign()
location.replace()
open()
element.srcdoc
XMLHttpRequest.open()
XMLHttpRequest.send()
jQuery.ajax()
$.ajax()
```

# 문제 
- 이 랩에는 DOM 베이스의 오픈 리다이렉션 취약점이 존재한다. 
- 랩을 풀려면 이 취약점을 exploit하여 victim을 exploit서버로 리다이렉트 시켜라. 

```
This lab contains a DOM-based open-redirection vulnerability. To solve this lab, exploit this vulnerability and redirect the victim to the exploit server.
```

# 풀이 
1. 일단 취약점이 있어보이는 Javascript 코드를 찾는다. 랩의 블로그 포스트 글을 보면 되돌아가기 버튼이 다음과 같은 코드로 이루어진 것을 알 수 있다. 

```html
<div class="is-linkback">
    <a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); location.href = returnUrl ? returnUrl[1] : "/"'>Back to Blog</a>
</div>
```

2. 분석을 위해서 onclick 이벤트시 동작하는 코드를 좀더 보기 쉽게 만들면 다음과 같다. 
- 정규표현식 `/url=(https?:\/\/.+)/`을 사용해서 location 의 값을 체크한 결과를 returnUrl 변수에 저장한다. 
- returnUrl 변수에 값이 존재하면 returnUrl 배열의 두번째 값을 location.href에 지정한다. (자바스크립트에서 exec함수를 사용하면  정규표현식의 괄호안 부분에 일치한 부분이 결과배열의 두번째 값에 들어간다.) 
- returnUrl 변수에 값이 존재하지 않으면 "/" 를 location.href에 지정한다. 

```js
returnUrl = /url=(https?:\/\/.+)/.exec(location); 
location.href = returnUrl ? returnUrl[1] : "/"'
```

3. 공격용 페이로드를 구상한다. 정규표현식 `/url=(https?:\/\/.+)/`를 잘 살펴본다. 웹 페이지의 location에 `url=https://` 와 같은 문자열이 포함되어 있으면 정규표현식과 매치(match)될 것이다. 즉, 다음과 같은 형태면 returnUrl 값이 https://exploit-0ad000f4045f11d483ed371001740054.exploit-server.net/ 가 되어, 되돌아가기 버튼을 눌렀을 때 exploit서버로 리다이렉트될 것이다. 

```html
https://0a2f009604c41143839b383100e10064.web-security-academy.net/post?postId=4&url=https://exploit-0ad000f4045f11d483ed371001740054.exploit-server.net/
```

![](/images/burp-academy-dom-based-4-1.png)
*Chrome의 디버거로 확인해본 모습*

4. 웹 브라우저로 위의 URL로 접속해보면 잠시 뒤 랩이 풀린다. 


![](/images/burp-academy-dom-based-4-success.png)
