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
- 문제 주소: https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation
- 취약점 설명페이지: https://portswigger.net/web-security/dom-based/cookie-manipulation
- 난이도: PRACTITIONER (보통)


# Dom-based Cookie Manipulation 이란? 
- 일부 Dom-based 취약점은 공격자가 일반적으로는 컨트롤할 수 없는 데이터를 컨트롤할 수 있게 만들어준다. 
- Dom-based Cookie Manipulation 은 공격자의 인풋이 쿠키의 값으로 전달될 때 발생한다. 
- 공격자는 이 취약점을 이용해 다른 사용자가 방문하면 사용자 쿠키에 임의의 값을 설정하는 URL을 구성할 수 있다. 
- 예를 들어, JavaScript가 Source로부터의 데이터를 document.cookie에 새니타이즈하지 않고 쓰는(Write) 경우 공격자는 쿠키에 임의의 값을 삽입할 수 있다. 

```js
document.cookie = 'cookieName='+location.hash.slice(1);
```

- `document.cookie` Sink로 인해 Dom-based Cookie Manipulation 가 일어날 수 있다. 

# 문제 개요
- 이 랩에는  DOM-based client-side cookie manipulation 취약점이 있다. 
- 랩을 풀려면 XSS를 발동시키는 쿠키를 삽입하여 다른 페이지에서 print()함수가 실행되도록 하라. 
- victim을 페이지로 유도하기 위해 exploit서버를 사용할 필요가 있다. 

```
This lab demonstrates DOM-based client-side cookie manipulation. To solve this lab, inject a cookie that will cause XSS on a different page and call the print() function. You will need to use the exploit server to direct the victim to the correct pages.
```

# 풀이
1. 취약점이 있는 곳을 찾는다. 제품 상세보기 페이지 (/product?productId=1)를 들어가보면 페이지에 다음과 같은 코드가 있다. window.location (Source)의 값을 document.cookie (Sink)에 쓰고 있다. 취약한 코드로 보인다. 

```html
<script>
    document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure'
</script>
```

2. 쿠키의 값을 확인해본다. `lastViewedProduct` 쿠키에 현재 페이지의 URL이 들어가는 것을 알 수 있다. 

![](/images/burp-academy-dom-based-5-1.png)

3. XSS가 가능한 곳을 찾는다. 동일하게 제품 상세보기 페이지에 XSS가 가능한 곳이 있다. Last viewed product 라는 링크에 URL값이 새니타이징되지 않고 그대로 들어가는 것을 알 수 있다. victim을 `https://0af900cc03b4997081ecb650007a0019.web-security-academy.net/product?productId=1&'><script>print()</script>` 과 같은 URL로 유도하면 print함수가 실행될 것이다. 

![](/images/burp-academy-dom-based-5-2.png) 

4. 그런데 랩 서버를 잘 살펴보면 재밌는 동작을 하는 것을 알 수 있다. XSS페이로드를 포함한 URL로 접근하여 `lastViewedProduct` 쿠키에 값이 저장되면, 다음에 웹 사이트에 방문했을 때 해당 값에 저장된 페이지로 리다이렉트시켜주는 것이다. 

![](/images/burp-academy-dom-based-5-3.png)

5. 위와 같은 관찰을 토대로 다음과 같은 페이로드를 만든다. 

```html
<iframe src="https://0af900cc03b4997081ecb650007a0019.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://0af900cc03b4997081ecb650007a0019.web-security-academy.net';window.x=1;">
```

동작 설명
- victim이 iframe에서 XSS 페이로드가 들어간 URL을 로드하면 lastViewedProduct 쿠키에 값이 저장된다. 
- 그 후에 onload 이벤트가 발동되어 window.x라는 값이 있는지를 확인한다.
- window.x 란 변수는 최초에는 없는 값이므로 (victim도 모르는 새에) victim은  https://0af900cc03b4997081ecb650007a0019.web-security-academy.net 로 리다이렉트 된다.
- window.x에 1이 저장된다. (두번째 방문부터는 리다이렉트가 되지 않는다)
- 리다이렉트된 사이트에서는 쿠키값을 토대로 해당 페이지로 리다이렉트시켜주므로 XSS 페이로드가 포함된 페이지로 리다이렉트되어 print함수가 실행된다. 

참고로, 단순히 victim을 다음 페이지로 유도하는 것 만으로도 print함수를 실행시킬 수는 있다. 그러나 쿠키 값 변조에 의한 XSS를 확인하기 위한 랩의 목적상 좀 더 복잡한 위의 페이로드를 사용한다고 이해하면 될 것 같다. 

```html
<iframe src="https://0af900cc03b4997081ecb650007a0019.web-security-academy.net/product?productId=1&'><script>print()</script>" >
```

 
6. exploit서버에서 페이로드를 저장후 Deliver to victim 버튼을 누르면 랩이 풀렸다는 메세지가 표시된다. 

![](/images/burp-academy-dom-based-5-success.png)