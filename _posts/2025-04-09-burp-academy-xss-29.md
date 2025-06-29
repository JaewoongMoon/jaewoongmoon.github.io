---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS with AngularJS sandbox escape and CSP"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-04-09 21:30:00 +0900
---

# 개요
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection
- 랩 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-and-csp
- PortSwigger Research(56글자로 AngularJS CSP 우회하기): https://portswigger.net/research/angularjs-csp-bypass-in-56-characters
- 난이도: EXPERT (어려움)


# 어떻게 AngularJS CSP 우회가 일어나는가? 
Content Security Policy (CSP) 우회는 표준 샌드박스 이스케이프와 유사한 방식으로 작동하지만, 일반적으로 HTML injection 이 포함된다. AngularJS에서 CSP 모드가 활성화되면 템플릿 표현식을 다르게 파싱하고 `Function` 생성자를 사용하지 않는다. 즉, (이전 랩에서 설명한) 표준 샌드박스 이스케이프는 더 이상 작동하지 않는다. 

특정 정책에 따라 CSP는 JavaScript 이벤트를 차단한다. 그러나 AngularJS는 대신 사용할 수 있는 자체 이벤트를 정의한다. 이벤트 내에서 AngularJS는 특수한 `$event` 객체를 정의한다. 이 객체는 브라우저 이벤트 객체를 참조한다. 이 객체를 사용하여 CSP를 우회할 수 있다. Chrome에서는 이 `$event/event` 객체에 존재하는 `path`로 불리는 특수한 속성이 있다. 이 속성은 객체의 배열을 포함하는데, 이는 이벤트를 실행시킨다. 마지막 속성은 항상 `window` 객체이며, 이를 사용하여 샌드박스 이스케이프를 수행할 수 있다. 이 배열을 `orderBy` 필터에 전달하면, 배열을 순회하고 마지막 요소(`window`객체)를 사용하여 `alert()`과 같은 전역 함수를 실행할 수 있다. 다음 코드는 이를 보여준다.

```html
<input autofocus ng-focus="$event.path|orderBy:'[].constructor.from([1],alert)'">
```

함수 `from()`이 사용된 것에 주목하자. 이는 객체를 배열로 변환하고 해당 배열의 모든 요소에 대해 (두 번째 인수에 지정된) 함수를 호출할 수 있게 해준다. 위의 경우에는 `alert()` 함수를 호출한다. 함수를 직접 호출할 수는 없는데, AngularJS 샌드박스가 코드를 파싱하여 `window` 객체가 함수를 호출하는 데 사용되었음을 감지하기 때문이다. 대신 `from()` 함수를 사용하면 샌드박스에서 `windows` 객체를 효과적으로 숨겨 악성 코드를 삽입할 수 있다. 

PortSwigger Research는 이 기술을 사용하여 [AngularJS를 사용하여 56자로 CSP를 우회하는 방법](https://portswigger.net/research/angularjs-csp-bypass-in-56-characters)을 만들었다.



## AngularJS 샌드박스 탈출을 통해서 CSP 우회하기 
이 랩은 길이 제한을 사용하므로 위의 벡터는 작동하지 않는다. 랩을 풀려면 AngularJS 샌드박스로부터 `window` 객체를 숨기는 다양한 방법을 생각해야 한다. 이를 수행하는 한 가지 방법은 다음과 같이 `array.map()` 함수를 사용하는 것이다.

```
[1].map(alert)
```

`map()` 함수는 파라메터로 함수를 받아들인 후, 배열의 각 항목에 대해 해당 함수를 호출한다. 이는 샌드박스를 우회하게 된다. 왜냐하면 `alert()` 함수에 대한 참조가 명시적으로 `window`를 참조하지 않고 사용되기 때문이다. 랩을 풀려면 AngularJS의 `window` 탐지에 걸리지 않고 `alert()`함수를 실행하는 다양한 방법을 시도해보라. 

# 랩개요 
- 이 랩은 AngularJS와 CSP를 사용하고 있다. 
- 랩을 풀려면 XSS공격을 수행하여 CSP을 우회하고, AngularJS샌드박스를 탈출하여 `document.cookie`를 alert창으로 출력하라. 

```
This lab uses CSP and AngularJS.

To solve the lab, perform a cross-site scripting attack that bypasses CSP, escapes the AngularJS sandbox, and alerts document.cookie.
```

# 풀이
1. 랩 서버를 살펴본다. 검색기능이 있다. 

![](/images/burp-academy-xss-29-1.png)

소스코드를 살펴보면 AngularJS 버전 1.4.4를 사용하고 있는 것을 알 수 있다. body 엘레먼트에 ng-app, ng-csp 등의 속성이 보이는데 AngularJS에서 사용하는 문법으로 보인다. 

![](/images/burp-academy-xss-29-2.png)

또한, 응답 헤더에는 다음과 같은 CSP 헤더가 포함되어 있다. 

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'self'
```

2. exploit서버로 가서 다음 코드를 서비스하도록 만든다. YOUR-LAB-ID를 적절히 변환한다. 

```html
<script>
location='https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>
```

3. "Store" 버튼을 누르고, 이어서 "View Exploit"을 선택하면 랩 서버 화면에서 alert창이 뜨는 것을 확인할 수 있다. 

4. "Deliver exploit to victim" 버튼을 누르면 잠시 후 랩이 풀린다. 

![](/images/burp-academy-xss-29-success.png)

5. 페이로드를 분석해본다. 쿼리 파라메터 부분을 URL디코딩해보면 다음과 같다. 

```html
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x
```

이 익스플로잇은 AngularJS의 `ng-focus` 이벤트를 사용하여 CSP를 우회하는 포커스 이벤트를 생성한다. 또한 AngularJS에서 이벤트 객체를 참조하는 변수인 `$event` 를 사용한다. 이 `path` 속성은 Chrome 전용이며 이벤트를 트리거한 요소의 배열을 포함한다. 배열의 마지막 요소에는 `window`객체가 포함된다. 

일반적으로 JavaScript에서 `|` 는 비트 연산이지만, AngularJS에서는 필터 연산을 가리킨다. 이 경우는 `orderBy` 필터다. 콜론은 필터에 전달되는 파라메터를 나타낸다. 파라메터에서 `alert` 함수를 직접 호출하는 대신 변수 `z` 에 할당한다. 함수는 `orderBy` 연산이 배열 `$event.path` 내부의 오브젝트를 통해 `window` 객체에 도달할 때만 호출된다. 이는 객체에 대한 명시적인 참조 없이도 window 범위에서 호출될 수 있으며 , AngularJS의 `window` 검사를 효과적으로 우회한 것을 의미한다. 


# 어떻게 Client-side template injection을 방지하는가
클라이언트 측 템플릿 주입 취약점을 방지하려면 신뢰할 수 없는 사용자 입력을 사용하여 템플릿이나 표현식을 생성하지 않아야 한다. 만약 이것이 현실적으로 불가능하다면, 클라이언트 측 템플릿에 템플릿 표현식 구문을 삽입하기 전에 사용자 입력에서 해당 구문을 필터링하는 것을 고려한다. 

HTML 인코딩만으로는 클라이언트 측 템플릿 주입 공격을 차단하기에 충분하지 않다. 프레임워크가 템플릿 표현식을 찾아 실행하기 전에 관련 콘텐츠에 대한 HTML 디코딩을 수행하기 때문이다.