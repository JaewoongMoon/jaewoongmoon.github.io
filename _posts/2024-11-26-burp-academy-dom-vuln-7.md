---
layout: post
title: "Burp Academy-DOM 관련 취약점: Clobbering DOM attributes to bypass HTML filters"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Dom 관련 취약점, XSS]
toc: true
last_modified_at: 2024-12-03 09:33:00 +0900
---

# 개요
- DOM based 타입의 XSS 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters
- 취약점 설명페이지: https://portswigger.net/web-security/dom-based/dom-clobbering
- 난이도: EXPERT (어려움)


# 또 다른 Dom Clobbering 테크닉 
또 다른 테크닉은 `input`엘레먼트와 함께 `form` 엘레먼트를 사용하는 것이다. 예를 들면, `attributes` 속성을 클로버링함으로써 클라이언트 사이드의 필터의 로직을 우회할 수 있다. 필터는 `attributes`속성을 순회하지만, `attributes `속성이 클로버링되어 있기 때문에 사실상 어떤 속성도 제거하지 못한다. 그 결과 공격자는 본래대로라면 필터링되었을 공격용  코드를 주입할 수 있게 된다. 

예를들어 다음 인젝션 코드를 보자. 

```html
<form onclick=alert(1)><input id=attributes>Click me
```

클라이언트측의 필터는 DOM을 순회하면서 화이트리스트에 등록된 `form`엘레먼트를 만난다. 일반적으로 필터는 `form`엘레먼트의 `attributes` 속성을 순회하면서 블랙리스트에 등록된 속성을 제거한다. 그러나, `attributes` 속성이 `input`엘레먼트에 의해 덮어쓰여졌기 때문에(클로버링), 필터는 대신에 `input` 엘레먼트를 순회한다. `input`엘레먼트는 정의되지 않은 길이를 가지고 있기 때문에, 필터의 `for`루프의 조건(예를 들면 `i<element.attributes.length`)가 충족되지 않아, 필터는 단순히 다른 엘레먼트로 넘어가 순회를 지속한다. (DOM 트리에서는 기본적으로 엘레먼트의 `attributes`속성이 length라는 값을 가지므로 일반적으로는 DOM 트리 순회가 되므로 문제가 없다. 하지만 DOM 클로버링으로 `attributes` 속성이 덮어쓰여졌기 때문에 length라는 속성이 존재하지 않게 된다.) 그 결과, `onclick` 이벤트는 모두 필터에 의해서 무시되며, 결과적으로 `alert()`함수의 실행을 허용하게 된다. 


# 문제 개요
- 이 랩은 DOM 클로버링에 취약한 HTMLJanitor 라이브러리를 사용하고 있다. 
- 랩을 풀려면 필터를 우회하는 공격 벡터를 만들어서 DOM 클로버링 테크닉으로 벡터를 주입하여 print()함수를 호출하라. 
- 공격벡터가 victim의 브라우저에서 실행되는 과정을 자동화하기 위해서 exploit서버가 필요할 수 있다. 
- 주의: 랩에서 의도한 해결책은 Chrome에서만 동작한다.

```
This lab uses the HTMLJanitor library, which is vulnerable to DOM clobbering. To solve this lab, construct a vector that bypasses the filter and uses DOM clobbering to inject a vector that calls the print() function. You may need to use the exploit server in order to make your vector auto-execute in the victim's browser.

Note
The intended solution to this lab will not work in Firefox. We recommend using Chrome to complete this lab.
```

# 풀이
1. 일단 랩 서버를 살펴본다. HTMLJanitor 라이브러리를 로드하는 것을 볼 수 있다. HTMLJanitor 라이브러리의 코드에서 attributes 를 새니타이징하는 부분을 살펴본다. 다음과 같다. 

```js
     // Sanitize attributes
      for (var a = 0; a < node.attributes.length; a += 1) {
        var attr = node.attributes[a];

        if (shouldRejectAttr(attr, allowedAttrs, node)) {
          node.removeAttribute(attr.name);
          // Shift the array to continue looping.
          a = a - 1;
        }
      }

```

2. 속성들에 접근하기 위해 node.attributes.length 로 접근하는 것을 알 수 있다. attributes 를 클로버링(덮어쓰기)할 수 있다면 필터링을 우회할 수 있을 것이다. 


3. 블로그 포스트 글에 가서 다음 코드를 저장한다. 

```html
<form id=x tabindex=0 onfocus=print()><input id=attributes>
```

4. exploit 서버에서 다음 코드를 저장한다. 
- "YOUR-LAB-ID" 부분을 자신의 랩 ID로 변경해준다. 
- postId 를 1번과정에서 코드를 저장한 글의 ID로 바꿔준다. 

```html
<iframe src=https://YOUR-LAB-ID.web-security-academy.net/post?postId=3 onload="setTimeout(()=>this.src=this.src+'#x',500)">
```


5. view exploit을 클릭하면 iframe에 랩 서버가 보인다. 페이지를 재로딩하면 print함수가 실행되는 것을 확인할 수 있다. 

![](/images/burp-academy-dom-based-7-1.png)

6. deliver to vicim 버튼을 누르면 문제가 풀렸다는 메세지가 출력된다. 

![](/images/burp-academy-dom-based-7-success.png)

설명(분석)
- HTMLJanitor 라이브러리는 `attributes`속성을 사용하여 HTML 속성을 필터링한다. 
- 그러나 공격자는 `<form id=x tabindex=0 onfocus=print()><input id=attributes>`를 삽입해서 `attributes`속성을 클로버링함으로써 length가 정의되지 않게 할 수 있다. 
- 이를 통해 라이브러리의 필터를 우회할 수 있다. (length 가 없으므로 체크가 동작하지 않는다.) 이는 어떤 속성이라도 `form`요소에 작성할 수 있다는 의미다. 이번 페이로드의 경우, `onfocus`속성을 사용하여 `print()`가 실행되도록 했다. 
- victim의 브라우저에서 `iframe`이 로드되면 500ms 지연 후 페이지 URL 끝에 `#x` 조각이 추가된다. 이 지연은 JavaScript가 실행되기 전에 블로그 글에 작성한 폼이 로드되도록 하는 데 필요하다. 그 후에 브라우저가 ID `x`가 있는 요소에 초점을 맞추게 되어 `onfocus`이벤트가 발동하게 된다. 

# 어떻게 DOM 클로버링을 막을 수 있는가? 
간단하게 말해서, 객체나 함수가 예상한 대로인지 확인하는 검사를 구현하여 DOM 클로버링 공격을 방지할 수 있다. 예를 들어, DOM 노드의 속성 속성이 실제로 `NamedNodeMap`의 인스턴스인지 확인할 수 있다. 이렇게 하면 해당 속성(property)이 attributes 속성이고 클로버링된 HTML 엘레먼트가 아님을 확인할 수 있다.

논리적 OR 연산자 `||`와 함께 전역 변수를 참조하는 코드를 작성하는 것도 피해야 한다. DOM 클로버링 취약점이 발생할 수 있기 때문이다.

요약하면:
- 객체와 함수가 합법적인지 확인하라. DOM을 필터링하는 경우 객체나 함수가 DOM 노드가 아닌지 확인한 후에 진행한다.
- 나쁜 코드 패턴을 피한다. 논리적 OR 연산자와 함께 전역 변수를 사용하는 것은 피해야 한다. 
- DOM 클로버링 취약점을 고려한 DOMPurify와 같은 잘 테스트된 라이브러리를 사용한다.

# 참고 
- https://portswigger.net/web-security/dom-based/dom-clobbering
- 돔 클로버링 한글 문서: https://intadd.tistory.com/143

