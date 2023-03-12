---
layout: post
title: "Burp Academy-서버사이드 프로토타입 오염(Server-side prototype pollution) 개념"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, 서버사이드 프로토타입 오염, Server-side prototype pollution]
toc: true
---

# 개요
- PortSwigger사의 [서버사이드 프로토타입 오염(Server-side prototype pollution)](https://portswigger.net/web-security/prototype-pollution/server-side){:target="_blank"} 을 보고 정리한 문서입니다. 

# 서버 사이드 프로토타입 오염(Server-side prototype pollution)
- Node.js와 같은 기술의 등장으로 자바스크립트는 이제 서버 백 엔드 개발에서도 널리 쓰이는 언어가 됐다. 
- 이 것은 자연히 `프로토타입 오염`이 백엔드 영역에서도 발생할 수 있는 취약점이 되었다는 것을 말한다. 
- 기본적인 핵심 컨셉은 클라이언트 사이드 프로토타입 오염과 동일하지만 몇 가지 어려운 점이 있다. 
- 이 문서에서 `서버 사이드 프로토타입 오염`에 대한 몇 가지 블랙박스 탐지 기법을 배울 것이다. 

# 왜 서버사이드 프로토타입 오염은 더 찾기 어려운가?
몇 가지 이유때문에 서버 사이드는 클라이언트 사이드보다 찾기 어렵다. 

- No source code access: 클라이언트 사이드와는 다르게 취약한 자바스크립트 코드를 볼 수 없다. 
- Lack of developer tools: 자바스크립트가 리모트 시스템에서 동작하고 있기 때문에 브레이크 포인트 등을 찍어서 디버깅하면서 오브젝트의 값을 확인할 수 없다. 
- The DoS problem: 프로토타입 오염이 성공하면 Dos를 유발시킬 수도 있다.  
- Pollution persistence: 클라이언트 사이드 프로토타입 오염은 페이지를 리로드하면 각종 값들이 새로운 상태에서 다시 테스트할 수 있다. 그러나 서버 사이드는 한번 오염시키면 Node 프로세스 내부에서 값이 지속되기 때문에 그런 것이 불가능하다. 

# polluted property reflection을 통해 서버 사이트 프로토타입 오염 찾기 
개발자들이 빠지기 쉬운 함정은 자바스크립트의 for...in 루프가 프로토타입 체인을 통해 상속된 속성을 포함하여 객체의 열거가능한 모든 속성을 interate 한다는 사실을 잊어버리거나 간과하는 것이다.

예를 들어 자바 스크립트 맵 객체를 사용하는 다음 코드를 보자. 이 코드를 실행하면 a, b, foo가 출력된다. (**중간에 오염시킨 foo속성도 같이 출력된다!**)

```js
const myObject = { a: 1, b: 2 };

// pollute the prototype with an arbitrary property
Object.prototype.foo = 'bar';

// confirm myObject doesn't have its own foo property
myObject.hasOwnProperty('foo'); // false

// list names of properties of myObject
for(const propertyKey in myObject){
    console.log(propertyKey);
}

// Output: a, b, foo
```

이는 배열에 대해서도 마찬가지이다. 다음 코드를 실행하면 배열의 키(인덱스)와 함께 오염시킨 foo가 함께 출력된다. 

```js
const myArray = ['a','b'];
Object.prototype.foo = 'bar';

for(const arrayKey in myArray){
    console.log(arrayKey);
}

// Output: 0, 1, foo
```

위 두가지 케이스에서, 만약 어플리케이션 응답을 통해 자바스크립트 오브젝트의 속성들을 확인할 수 있다면, 이 것이 서버 사이트 프로토타입 오염여부를 테스트할 수 있는 가장 간단한 방법이 된다. 

POST 나 PUT 요청으로 JSON 데이터를 전송하는 API가 유력한 대상이 될 수 있다. 

```http 
POST /user/update HTTP/1.1
Host: vulnerable-website.com
...
{
    "user":"wiener",
    "firstName":"Peter",
    "lastName":"Wiener",
    "__proto__":{
        "foo":"bar"
    }
}
```

만약 웹 사이트가 취약하다면 다음과 같이 프로토타입 오염된 오브젝트가 응답에 포함될 것이다. (혹은 렌더링된 html페이지에서 오염된 속성을 확인할 수 있을 것이다.)

```http
HTTP/1.1 200 OK
...
{
    "username":"wiener",
    "firstName":"Peter",
    "lastName":"Wiener",
    "foo":"bar"
}
```