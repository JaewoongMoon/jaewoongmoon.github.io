---
layout: post
title: "Burp Academy 문제풀이 - Client-side prototype pollution in third-party libraries"
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

# 풀이 
이 문제부터는 `Dom Invader`를 사용할 필요가 있다. 자세한 설명은 [여기](https://portswigger.net/burp/documentation/desktop/tools/dom-invader){:target="_blank"}에 있다. 

Dom Invader를 켠다. 

![dom invader 켜기](/images/burp-academy-prototype-pollution-3-enable-dom-invader.png)

Dom Invader를 켰으면, 이어서 Prototype Pollution 테스트 기능을 켠다. 

![Prototype Pollution 켜기](/images/burp-academy-prototype-pollution-3-enable-dom-invader-prototype-pollution.png)


문제사이트에서 Dom Invator Test 버튼을 클릭해서 Prototype Pollution이 가능한지 테스트할 수 있다. 

![dom invader start test](/images/burp-academy-prototype-pollution-3-dom-invader-tab.png)

테스트 결과 다음과 같이 Prototype Pollution이 가능하다는 것을 확인할 수 있다. 
![dom invader test result](/images/burp-academy-prototype-pollution-3-dom-invader-test-function.png)


그러면 다음으로 실제로 Prototype Pollution 공격을 사용할 수 있는 곳을 찾아야 한다. `Scan for gadgets`버튼을 클릭한다. 그러면 다음과 같이 스캔이 진행된다. 

![dom invader scan](/images/burp-academy-prototype-pollution-3-find-dom-invader-synk-processing.png)

취약점 스캔이 끝나면 다음과 같이 한 개 공격가능한 곳(sink) 를 발견했다는 메세지가 뜬다. 

![dom invader scan result](/images/burp-academy-prototype-pollution-3-find-dom-invader-synk-result.png)

F12 를 눌러서 `Exploit`버튼을 클릭한다. 

![dom invader exploit](/images/burp-academy-prototype-pollution-3-find-dom-invader-synk.png)

그러면 다음과 같이 alert 창이 뜨는 것을 확인할 수 있다. 

![dom invader exploit result](/images/burp-academy-prototype-pollution-3-test-payload.png)

`alert(1)`이 실행되었으므로 이것을 `alert(document.cookie)`가 실행되도록 조금 수정한다. 
```
https://0ab5005a046b393dc567ebbb00b1000a.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29
```

Go to exploit server 를 클릭해 Exploit 서버의응답의 헤더부분을 다음과 같이 수정하고 저장한다. 그리고 Deliver to Victim 버튼을 클릭한다. 

```
HTTP/1.1 302 OK
Content-Type: text/html; charset=utf-8
Location: https://0ab5005a046b393dc567ebbb00b1000a.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29
```

그러면 다음과 같이 성공했다는 팝업을 볼 수 있다. 

![dom invader](/images/burp-academy-prototype-pollution-3-success.png)

Dom Invader, 정말 편하다. 앞으로 클라이언트 사이드(Client-side) 취약점을 찾을 때 많이 사용하게 될 것 같다. 