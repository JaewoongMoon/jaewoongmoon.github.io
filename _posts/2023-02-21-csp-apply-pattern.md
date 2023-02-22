---
layout: post
title: "CSP 헤더 적용 패턴정리 - 인라인 스크립트 해시, 별도 스크립트 파일"
categories: [CSP 헤더, XSS 방어]
tags: [CSP 헤더, XSS 방어]
toc: true
---

# 개요
- CSP 헤더를 적용하는 패턴을 몇 개 정리해둔다. 
- 인라인 스크립트를 사용하는 경우와 별도 스크립트 파일로 분리하는 경우를 테스트해본다. 
- 테스트도구: html페이지, js파일, nginx웹서버
- 테스트일자: 2023년 2월 21일
- 테스트 브라우저: 크롬 Version 110.0.5481.104 (Official Build) (64-bit) 

# 인라인 스크립트를 사용하는 경우
- 인라인 스크립트란 html 페이지 내에 자바스크립트 코드가 내장되어 있는 경우를 말한다. 
- 이 방식으로 개발된 사이트는 꽤 많을 것으로 생각된다. 
- CSP 헤더를 적용할 경우, 기본적으로 모든 인라인 스크립트 실행이 금지된다. 
- CSP 헤더를 적용하면서 인라인 스크립트를 사용하려면 `unsafe-inline` 설정을 추가하거나 해시(hash) 또는 난스(nonce)를 적용해야 한다. 

## unsafe-inline 추가하기 
- 다음과 같이 CSP헤더에 `'unsafe-inline'`을 추가한다. 
- 그러나 이 설정은 보안상 큰 메리트가 없다. 
- XSS 공격이 대부분 인라인 스크립트 삽입으로 이루어지기 떄문에 인라인 스크립트 실행을 허용할 경우 CSP 헤더 본래의 목적인 XSS방어에 실패하는 결과로 이어지기 떄문이다. 
- 따라서 `'unsafe-inline'`을 추가하는 것은 Bad Practice로 여겨진다. 

```html
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8" />
<meta http-equiv="content-security-policy" content="default-src 'self' 'unsafe-inline'">
<title></title>
</head>
<body>

<script type="text/javascript">
alert(1);
</script>

</body>
</html>
```

## 해시 적용하기 
- `unsafe-inline`키워드를 사용하고 싶지 않을 경우에 해시를 지정할 수 있다. 
- 인라인 스크립트의 해시 값을 CSP 헤더에 지정해둔다. 
- 해시를 계산하는 방법은 [여기]({% post_url 2023-02-21-csp-hash-calc %})를 참고한다. 

```html
<!DOCTYPE html>
<html>
    <head>
    <meta charset="utf-8" />
    <meta http-equiv="content-security-policy" content="default-src 'self' 'sha256-5jFwrAK0UV47oFbVg/iCCBbxD8X1w+QvoOUepu4C2YA='">
    <title></title>
    </head>
<body>
    <script type="text/javascript">
    alert(1);
    </script>
</body>
</html>
```

### 동적으로 DOM을 생성하는 스크립트에 해시 적용
몇 가지를 추가로 테스트해 본다. 위의 샘플은 아주 간단한 스크립트였다. 좀 더 복잡한, 예를 들어, 동적으로 DOM 객체를 생성하는 인라인 스크립트도 해시를 적용해서 실행가능할까?

```html
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8" />
<meta http-equiv="content-security-policy" content="default-src 'self' 'sha256-VjOu3FlOq156ykkk44BH5bKpGhc3JpUb+UheC+9h7NI='">
<title></title>
</head>
<body>

<script type="text/javascript">
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const url = urlParams.get('url')
var a_tag = document.createElement("a");
a_tag.setAttribute("src", url);
document.body.appendChild(a_tag);
</script>

</body>
</html>
```

테스트해보니 잘 실행되는 것을 확인했다. 스크린샷을 보면 a 태그가 추가되어 있는 것을 알 수 있다. 

![DOM 생성 스크립트 실행결과](/images/csp-make-dom-element.png)

### 동적으로 DOM을 생성하는 스크립트인데 그 것이 생성하는 DOM이 iframe인 경우
DOM이 iframe인 경우에도 잘 동작할까? iframe에 http://google.com의 내용을 보여주도록 만들어봣다. 

```html 
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8" />
<meta http-equiv="content-security-policy" content="default-src 'self' 'sha256-//H4vo7w6Nyh4/aeucv/w/qU4UNQK0sy1EE9G+72/Do='">
<title></title>
</head>
<body>

<script type="text/javascript">
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const url = urlParams.get('url')
var ifrm = document.createElement("iframe");
ifrm.setAttribute("src", url);
ifrm.style.width = "640px";
ifrm.style.height = "480px";
document.body.appendChild(ifrm);
</script>

</body>
</html>
```

결과는 다음과 같다. iframe을 쓰고 싶으면, frame-src를 추가해야 한다고 한다. 

```
Refused to frame 'http://google.com/' because it violates the following Content Security Policy directive: "default-src 'self'". Note that 'frame-src' was not explicitly set, so 'default-src' is used as a fallback.
```

![iframe이 거부된 경우](/images/csp-iframe-deny.png)

테스트를 해보니 frame-src에 추가를 해도 크롬이 못 알아먹는다. 다음과 같이 default-src에 명시해주는게 더 확실했다. 

```html
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8" />
<meta http-equiv="content-security-policy" content="default-src 'self' 'sha256-K9V+UkGb3oEpPBqs6+4fNQfTFoQAulZsD25VVEO8ELM=' www.example.com">
<title></title>
</head>
<body>

<script type="text/javascript">
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const url = urlParams.get('url')
var ifrm = document.createElement("iframe");
ifrm.setAttribute("src", url);
ifrm.style.width = "640px";
ifrm.style.height = "480px";
document.body.appendChild(ifrm);
</script>

</body>
</html>
```

어쨌든, 몇 가지 테스트를 통해서 동적으로 DOM을 생성하는 코드여도 CSP 해더 해시를 적용해서 스크립트를 실행할 수 있다는 것을 확인했다. 

## 인라인 스크립트 해시 지정 테스트 감상
- html페이지에 리소스를 추가할 때마다 해시를 추가해야 하는 것이 불편하다. 
- 더군다나 해시 값은 원본 내용이 조금만 달라져도 크게 달라진다. 
- 거기에다 크롬이 계산하는 해시값과 openssl 로 계산한 해시값이 다른 경우도 있어서 더욱 적용하기 불편했다. 
- CSP 버전2부터 사용가능하게 된 nonce를 사용하는게 더 편하다는 생각이 든다. 

## 인라인 스크립트 정리 
- CSP 헤더를 사용하면서 인라인 스크립트를 사용하려면 unsafe-inline 지정 혹은 Hash/Nonce 지정을 해야한다. 
- unsafe-inline은 보안상 추천되지 않는다. XSS를 허용할 틈을 만들어주기 때문이다. usnafe-inline 보다는 Hash/Nonce사용이 추천된다. 

# 자바스크립트를 별도 파일로 분리하는 경우
자바스크립트를 별도 파일로 분리하는 경우는 어떨까? 이 경우에도 해시값 지정이 필요할까?   
테스트해보니, 별도 파일로 분리하면 해시값을 지정하지 않아도 되었다. 별도 파일로 분리하면 해시를 지정하는 불편함이 없어지는 메리트가 있다는 것을 알았다. 

```html 
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8" />
<meta http-equiv="content-security-policy" content="default-src 'self'">
<script type="text/javascript" src="jquery.js"></script>
<script type="text/javascript" src="test.js"></script>
<title></title>
</head>
<body>

<div id="div-1">
    Test Value
</div>
</body>
</html>
```

test.js

```js
alert($("#div-1").val());
```

# 인라인 스크립트 vs 별도 파일 분리 
- CSP 헤더를 적용할 때 인라인 스크립트 방식과 별도 파일 분리 방식의 보안레벨을 비교해보자. 
- 예를 들어, 인라인 스크립트와 별도 파일 모두에 XSS취약점이 있는 경우는 어떻게 동작할까?

## 인라인스크립트 해시를 사용하는 경우 
- 테스트를 위해 다음과 같이 DOM-XSS 취약점이 있는 샘플을 만들었다. 
- https://owasp.org/www-community/attacks/DOM_Based_XSS 의 샘플 코드를 참고했다. 

```html
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8" />
<meta http-equiv="content-security-policy" content="default-src 'self' 'sha256-BDbcv5a0Y/snkMZHZ4R4+gzEWxDhLZfnYzvxFZhqk20='">
<title></title>
</head>
<body>
<!-- Inline Script DOM-XSS -->
Select your language:

<select><script>
    
document.write("<OPTION value=1>"+decodeURI(document.location.href.substring(document.location.href.indexOf("default=")+8))+"</OPTION>");
    
document.write("<OPTION value=2>English</OPTION>");
    
</script></select>
</body>
</html>
```

`#default=<script>alert(document.cookie)<script>` 등으로 XSS 테스트를 시도해보면 alert창이 실행되지 않는 것을 확인할 수 있다. CSP 헤더에 지정한 해시 값에 의해 삽입한 자바스크립트 실행이 금지된 것이다!     
이유가 뭘까? XSS 페이로드는 script태그를 html 페이지에 삽입한다. 이 script 태그의 해시 값은 CSP 헤더에 지정된 값이 아니다. 따라서 브라우저는 이 스크립트 실행을 거부한다. 따라서 XSS에 대해 방어가 되는 것이다. 

![CSP 헤더 해시 XSS 방어1](/images/csp-hash-xss-protection.png)

※ 해시 사용이 아니라 unsafe-inline 을 설정한 경우에는 당연히 스크립트가 실행된다. 

## 별도 스크립트 파일로 분리한 경우 
다음과 같이 html파일과 js파일을 분리했다. 

```html
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8" />
<meta http-equiv="content-security-policy" content="default-src 'self'">
<script type="text/javascript" src="jquery.js"></script>
<title></title>
</head>
<body>
Select your language:

<select>
<script type="text/javascript" src="xss.js"></script>
</select>
</body>
</html>
```

```js
    
document.write("<OPTION value=1>"+decodeURI(document.location.href.substring(document.location.href.indexOf("default=")+8))+"</OPTION>");
    
document.write("<OPTION value=2>English</OPTION>");
    
```

이 상태에서 XSS 테스트를 실행해보면 삽입한 자바스크립트 실행이 안되는 것을 확인할 수 있다. 

![CSP 헤더 별도 파일 XSS 방어1](/images/csp-seperate-js-xss-protection.png)

이유가 뭘까? XSS 페이로드는 script태그를 html 페이지에 삽입한다. 이 경우, 인라인 스크립트가 된다. CSP 헤더에 의해 인라인 스크립트 실행이 기존적으로 금지되어 있기 때문에 XSS로 삽입한 스크립트는 실행이 안된다! 따라서 XSS에 대해 방어가 되는 것이다. 

## 인라인 스크립트 vs 별도 파일 분리 결론 
양쪽 방식 모두 원리는 조금 다르지만 XSS 방어에 성공했다. 현재로서는 둘 사이의 보안 레벨은 차이가 없어 보인다. 

# 인라인 스크립트 vs 별도 파일 분리 추가 테스트 
XSS로 script 태그를 새롭게 삽입하는 경우가 아니라 원래 있던 script내부에 직접 코드가 삽입 가능한 경우는 어떨까? 예를들면 다음과 같은 경우이다. url이라는 파라메터로 앵커태그(a 태그)의 src속성에 직접 코드를 삽입할 수 있게 되어 있다. 이 경우, script 태그를 추가로 삽입하는게 아니라 `javascript:alert('XSS')`등으로 코드를 삽입하는 것이 가능하다. 

```html
<script type="text/javascript">
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const url = urlParams.get('url')
var a_tag = document.createElement("a");
a_tag.setAttribute("href", url);
a_tag.innerHTML = "Click me!";
document.body.appendChild(a_tag);
</script>
```

## 인라인 스크립트 해시 

```html 
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8" />
<meta http-equiv="content-security-policy" content="default-src 'self' 'sha256-pl/lz98ZmvmlJse+bLRS4BgXXpIfygbrvE0wq30gl1U='">
<title></title>
</head>
<body>

<script type="text/javascript">
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const url = urlParams.get('url')
var a_tag = document.createElement("a");
a_tag.setAttribute("href", url);
a_tag.innerHTML = "Click me!";
document.body.appendChild(a_tag);
</script>

</body>
</html>
```
`javascript:alert(1);`이라는 페이로드로 테스트해보면 다음과 같은 에러 메세지와 함께 실행을 거부하는 것을 알 수 있다. 
(평범하게 http://google.com 같은 페이로드인 경우에는 잘 동작한다.)

![CSP 헤더 해시 XSS 방어2](/images/csp-hash-xss-protection-2.png)

이 것으로 유추할 수 있는 점은 브라우저가 페이로드로 인해 추가된 코드를 포함한 실행시점의 자바스크립트 해시값를 계산해서 CSP 헤더에 지정된 해시값과 비교한다는 점이다. 해시값이 달라지기 때문에 스크립트 실행을 거부하고, 따라서 XSS 방어가 된다. 꽤 강력하다. 대부분 XSS 공격은 방어할 수 있을 것 같다. 

## 별도 파일 분리 
별도 파일 분리했을 때도 XSS를 잘 방어할까? 다음과 같이 만들었다. 

```html
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8" />
<meta http-equiv="content-security-policy" content="default-src 'self'">
<title></title>
</head>
<body>
<script type="text/javascript" src="xss2.js"></script>
</body>
</html>
```

xss2.js 
```js
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const url = urlParams.get('url')
var a_tag = document.createElement("a");
a_tag.setAttribute("href", url);
a_tag.innerHTML = "Click me!";
document.body.appendChild(a_tag);
```

테스트해보면 다음과 같이 잘 방어하는 것을 알 수 있다. 에러메세지를 보면, CSP 헤더때문에 인라인 스크립트 실행을 거부했다고 나와있다. 브라우저는 XSS페이로드로 script 태그를 삽입하는 것 뿐아니라, html페이지 내에서 DOM의 속성등에 동적으로 추가되는 자바스크립트 코드도 인라인 스크립트로 취급하는 것을 알 수 있다.  

![CSP 헤더 별도 파일 XSS 방어2](/images/csp-seperate-js-xss-protection-2.png)

# 결론
- CSP헤더에서 인라인 스크립트에 해시를 적용하는 방법과 별도 파일로 분리하는 방법을 비교해봤다. 
- 보안 레벨은 둘 다 동일하다. 하지만, 별도 파일로 분리하는 방법이 파일 관리면이나 CSP헤더를 더 심플하게 작성할 수 있다는 점, 캐싱에 유리하다는 점 등 몇 가지 더 메리트가 있다고 생각된다. 
- 가능하면 자바스크립트는 별도 파일로 분리해서 CSP 헤더를 적용하자. 