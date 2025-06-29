---
layout: post
title: "Burp Academy-XSS 취약점: DOM XSS in document.write sink using source location.search"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-05-07 21:55:00 +0900
---

# 개요
- Dom기반 XSS 취약점 랩이다.
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink
- 취약점 설명: https://portswigger.net/web-security/cross-site-scripting/dom-based
- 난이도: APPRENTICE (쉬움)

# DOM 기반 크로스 사이트 스크립팅이란?
DOM 기반 XSS 취약점은 일반적으로 JavaScript가 URL과 같이 공격자가 제어할 수 있는 소스에서 데이터를 가져와 `eval()` 또는 `innerHTML` 과 같은 동적 코드 실행을 지원하는 싱크로 전달할 때 발생한다. 이를 통해 공격자는 악성 JavaScript를 실행할 수 있으며, 이를 통해 다른 사용자의 계정을 탈취할 수 있다. 

(공격자가 입력을 제어 가능한 부분을 소스(source)라고 한다. 소스로 입력된 데이터가 실행되는 곳을 싱크(sink)라고 한다.)

DOM 기반 XSS 공격을 실행하려면 데이터를 소스에 배치하여 싱크로 전달되게 하여 임의의 JavaScript를 실행해야 한다.

DOM XSS의 가장 흔한 소스는 URL이며, 일반적으로 `window.location` 객체를 통해 접근한다. 공격자는 쿼리 문자열과 URL의 조각(fragment) 부분에 페이로드를 포함하여 피해자를 취약한 페이지로 보내는 링크를 생성할 수 있다. 404 페이지나 PHP를 실행하는 웹사이트를 대상으로 하는 경우와 같이 특정 상황에서는 페이로드가 경로에 포함될 수도 있다.

소스와 싱크 간의 오염 흐름에 대한 자세한 설명은 [DOM 기반 취약점](https://portswigger.net/web-security/dom-based) 페이지를 참조하라.

# DOM 기반 크로스 사이트 스크립팅을 테스트하는 방법
대부분의 DOM XSS 취약점은 Burp Suite의 웹 취약점 스캐너를 사용하여 빠르게 찾을 수 있다. DOM 기반 크로스 사이트 스크립팅을 수동으로 테스트하려면 일반적으로 Chrome과 같은 개발자 도구가 있는 브라우저를 사용해야 한다. 사용 가능한 소스(Source)를 차례로 살펴보고 개별적으로 테스트해야 한다.

## HTML 싱크 테스트하기
HTML 싱크에 들어가는 DOM XSS를 테스트하려면 소스에 임의의 영숫자 문자열(예: `location.search`)을 입력한 다음 개발자 도구를 사용하여 HTML을 검사하고 문자열이 나타나는 위치를 찾는다. 브라우저의 "소스 보기" 옵션은 JavaScript에 의해 HTML에 적용된 변경 사항이 반영되지 않으므로 DOM XSS 테스트에는 적절하지 않다. Chrome 개발자 도구에서는 Control+F( MacOS에서는 `Command+F`)를 사용하여 DOM에서 문자열을 검색할 수 있다.

DOM 내에서 문자열이 나타나는 각 위치에 대해 컨텍스트를 식별해야 한다. 이 컨텍스트를 기반으로 입력 내용을 변경하면서 문자열이 처리되는 방식을 확인해야 한다. 예를 들어, 문자열이 큰따옴표로 묶인 속성 안에 나타나는 경우, 문자열에 큰따옴표를 삽입하여 속성을 벗어날 수 있는지 확인한다.

브라우저마다 URL 인코딩 방식이 다름에 주의하자. Chrome, Firefox, Safari는 `location.search` 및 `location.hash`를 URL 인코딩하는 반면, IE11과 Microsoft Edge(Chromium 이전 버전)는 이러한 소스를 URL 인코딩하지 않는다. 데이터가 처리되기 전에 URL 인코딩되면 XSS 공격이 성공할 가능성이 낮다. 

## JavaScript 실행 싱크 테스트하기
JavaScript 실행 싱크 테스트는 조금 더 어렵다. 이 타입의 싱크는 입력 내용이 DOM 내 어디에도 나타나지 않기 때문에 검색할 수 없기 때문이다. 대신 JavaScript 디버거를 사용하여 입력 내용이 싱크로 전송되는지, 전송되다면 어떻게 전송되는지를 확인해야 한다. 

각 잠재적 소스(예: `location`)에 대해, 먼저 페이지의 JavaScript 코드에서 소스가 참조되는 부분을 찾아야 한다. Chrome 개발자 도구에서는 `Control+Shift+F`(MacOS에서는 `Command+Alt+F`)를 사용하여 페이지의 모든 JavaScript 코드에서 소스를 검색할 수 있다. 

소스가 읽히는 위치를 찾으면 JavaScript 디버거를 사용하여 중단점을 추가하고 소스 값이 어떻게 사용되는지 확인할 수 있다. 소스가 다른 변수에 할당되는 것을 발견할 수도 있을 것이다. 이 경우 검색 기능을 다시 사용하여 이러한 변수를 추적하고 싱크로 전달되는지 확인해야 한다. 소스에서 생성된 데이터가 할당되는 싱크를 찾으면 디버거를 사용하여 값을 검사할 수 있다. 변수 위에 마우스를 올려놓으면 싱크로 전송되기 전에 해당 값이 표시된다. 그런 다음 HTML 싱크와 마찬가지로 입력을 수정하여 XSS 공격이 성공하는지 확인해야 한다.


## DOM Invader를 사용하여 DOM XSS 테스트하기
실제 환경에서 DOM XSS를 식별하고 exploit하는 것은 지루한 작업일 수 있으며, 복잡하고 최소화된(압축된) JavaScript를 수동으로 검색해야 하는 경우가 많다. 하지만 Burp 브라우저를 사용하면 내장된 DOM Invader 확장 프로그램을 활용하여 많은 작업을 대신 수행시킬 수 있다. 

# 다양한 소스와 싱크를 사용한 DOM XSS 활용
원론적으로, 소스에서 싱크로 데이터가 전달될 수 있는 실행 가능 경로가 있는 경우 웹사이트는 DOM 기반 크로스 사이트 스크립팅에 취약하다. 실제로 소스와 싱크마다 exploit 가능성에 영향을 미칠 수 있는 속성과 동작이 다르며, 이에 따라 필요한 기법이 결정된다. 또한, 웹사이트 스크립트는 취약점 exploit을 시도할 때 반드시 거쳐야 하는 값의 유효성 검사나 기타 데이터 처리를 수행할 수도 있다. DOM 기반 취약점과 관련된 다양한 싱크가 있습니다. 자세한 내용은 [목록](https://portswigger.net/web-security/cross-site-scripting/dom-based#which-sinks-can-lead-to-dom-xss-vulnerabilities)을 참조하자.

`document.write`싱크는 `script`요소와 함께 작동하므로 아래와 같은 간단한 페이로드를 사용할 수 있다.

```html
document.write('... <script>alert(document.domain)</script> ...');
```

# 랩 개요
- 이 랩은 검색 쿼리 추적 기능에 DOM 기반 크로스 사이트 스크립팅 취약점을 포함하고 있다.
- 이 취약점은  페이지에 데이터를 쓰는 `document.write` JavaScript 함수를 사용한다. 
- 이 `document.write` 함수는 `location.search`의 데이터를 사용하여 호출되며 , 웹사이트 URL을 사용하여 제어할 수 있다.
- 이 랩을 풀려면 `alert` 함수를 호출하는 XSS 공격을 수행하라.

```
This lab contains a DOM-based cross-site scripting vulnerability in the search query tracking functionality. It uses the JavaScript document.write function, which writes data out to the page. The document.write function is called with data from location.search, which you can control using the website URL.

To solve this lab, perform a cross-site scripting attack that calls the alert function.
```

# 도전
1. 일단 Dom기반 XSS취약점이 존재하는 곳을 특정해야 한다. 랩 설명에서는 검색 쿼리 추적 기능에 취약점이 존재한다고 되어 있다. 검색을 해본다. 

![](/images/burp-academy-xss-3-1.png)

2. 검색 결과 페이지를 살펴보면 다음과 같은 인라인 Javascript코드가 페이지에 포함되어 있는 것을 볼 수 있다. `window.location.search`의 값이 img태그를 생성하는 `document.write` 함수의 입력으로 전달되는 것을 알 수 있다. 공격자가 제어가능한 입력(Source)의 값이 페이지에 출력하는 `document.write`의 입력값으로 전달되었으므로 Sink다. Dom기반 XSS가 가능해보인다. 

```html
<script>
    function trackSearch(query) {
        document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
    }
    var query = (new URLSearchParams(window.location.search)).get('search');
    if(query) {
        trackSearch(query);
    }
</script>
```

3. 그러면 이어서 어떤 페이로드를 사용할지 검토한다. img 태그의 속성(attribute)로 넣을 수 있으므로, `' onload=alert'`이면 적절해 보인다. 이 페이로드로 검색해본다.  

4. 결과는 다음과 같다. javascript가 동작하지 않았다. 쌍따옴표가 닫히지 않아서 페이로드가 src속성의 값으로 인식되고 있다. 

![](/images/burp-academy-xss-3-2.png)

5. 페이로드를 바꾼다. 쌍따옴표를 사용한다. 다음과 같다.  

```js
" onload=alert(); x='
```

6. 결과는 다음과 같다. 이번에는 아예 img태그가 생성되지 않았다. 브라우저의 콘솔창에도 아무런 에러 메세지가 출력되지 않았다. 서버측에서 페이로드가 무효화처리된 것 같다. 

![](/images/burp-academy-xss-3-3.png)

7. XSS페이로드를 img 태그의 속성으로 넣는 것을 포기하고, img태그를 닫은 뒤, 새로운 script태그를 추가하는 방법으로 가보자. 다음 페이로드를 사용한다. 

```js
"/><script>alert(document.domain)</script>
```

8. 결과는 다음과 같다. 페이로드가 페이지에 삽입되어, script태그가 유효한 상태가 되었다. 페이지가 로드되면 alert함수가 실행된다.

![](/images/burp-academy-xss-3-4.png)

9. 랩이 풀렸다. 

![](/images/burp-academy-xss-3-success.png)