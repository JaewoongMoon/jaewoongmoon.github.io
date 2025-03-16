---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS into HTML context with all tags blocked except custom ones"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2024-09-24 21:55:00 +0900
---

# 개요
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/contexts
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked
- 난이도: PRACTITIONER (보통)


# 랩 개요 
- 이 랩은 모든 커스텀태그를 제외한 모든 HTML태그를 블록한다. 
- 랩을 풀려면 XSS공격을 수행해서 커스텀 태그를 주입해서 document.cookie 의 값을 표시하는 alert창을 실행시켜라. 

```
This lab blocks all HTML tags except custom ones.

To solve the lab, perform a cross-site scripting attack that injects a custom tag and automatically alerts document.cookie.
```

# 도전 
1. 블로그 검색기능에서 `<custom>alert(1);</custom>`으로 검색해보면 커스텀태그는 에스케이프 처리되지 않고 화면에 표시되는 것을 알 수 있다. 나머지 HTML에서 정의되어 있는 태그는 모두 사용할 수 없게 되어 있다. 

![](/images/burp-academy-xss-18-1.png)

2. 커스텀 태그에서 어떻게 XSS를 발동시킬 수 있을까? 아마 사용가능한 이벤트가 있다면 발동시킬 수 있을 것이다. XSS 17번 문제에서 썼던 Intruder를 사용한 사용가능한 이벤트를 확인하는 방법을 사용해보자. 

3. Intruder를 세팅하고 결과를 확인한다. 

![](/images/burp-academy-xss-18-2.png)

의외로 모든 이벤트가 사용이 가능했다. 

![](/images/burp-academy-xss-18-3.png)

4. 페이로드 `<custom onload="javascript:alert(document.cookie);">` 로 검색을 해보았다. 

그런데 결과를 보면 다음과 같이 HTML페이지에 태그가 포함되지만 코드는 실행이 안되는 것을 알 수 있다. 

![](/images/burp-academy-xss-18-4.png)

5. 커스텀 태그에서는 이벤트가 발생이 안되는 것일까? 음... 내일 이어서 생각해본다. 

6. 답을 본다. 다음을 exploit서버에 저장한 뒤에 victim 에게 전송하라고 한다. 

```html
<script>
location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>
```

7. 페이로드를 분석해본다. 페이로드 부분을 디코딩해보면 다음과 같이 생겼다. 

```html
<xss+id=x+onfocus=alert(document.cookie) tabindex=1>#x
```

이 페이로드는 자동적으로 자바스크립트가 호출되도록 고안되었다. 
ID x를 가진 사용자 정의 태그를 생성한다. 여기에는 alert 함수를 트리거하는 onfocus 이벤트 핸들러가 포함된다. URL 끝의 해시는 페이지가 로드되는 즉시 이 요소에 초점을 맞추도록(onfocus 되도록) 한다. 

8. 실제로 해보면 alert창이 뜬다. Deliver to victim을 선택하면 잠시 뒤 문제가 풀렸다는 메세지가 표시된다. (아무런 반응이 없을 때도 있다. 이럴 때는 시간을 두고 다른 랩에서 시도해보면 메세지가 뜬다.)

![](/images/burp-academy-xss-18-5.png)

