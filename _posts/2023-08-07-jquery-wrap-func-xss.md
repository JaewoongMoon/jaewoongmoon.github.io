---
layout: post
title: "jQuery의 wrap함수로 XSS가 가능한지 확인하기"
categories: [보안취약점, jQuery, XSS]
tags: [보안취약점, jQuery, XSS, wrap 함수]
toc: true
last_modified_at: 2023-08-07 15:55:00 +0900
---

# 개요
jquery 의 wrap함수에서 XSS가 발생하는지 검증해본다. 


# jQuery wrap함수 사양
jQuery의 wrap함수는 어떤 DOM객체을 감싸는 DOM객체를 추가해주는 함수다. 예를 들면 다음와 같이 사용한다. <p> 를 <div> 로 감싸준다. 

```js
$("button").click(function(){
  $("p").wrap("<div></div>");
});

```

결과는 이렇게 된다. 

```html
<div>
    <p>
</div>
```

# wrap함수가 sink라는 것을 확인
wrap함수가 Dom-XSS에 말하는 sink라는 것을 확인하려면 코드를 전달했을 때, 그 코드가 실행되는지 확인하면 된다. 
wrap함수에 다음과 같은 페이로드가 전달되면 alert()함수가 실행된다. (디버거 콘솔등으로 확인할 수 있다.) 따라서 wrap함수에서 XSS가 발생할 수 있다는 것을 알 수 있다. 

```js
$("p").wrap("<img src=1 onerror=alert(1);>"); 
```

# Source를 확인
Source란 공격자가 컨트롤가능한 데이터를 받아들이는 자바스크립트 속성(프로퍼티)이다. location.search (쿼리스트링을 얻어오는 코드)등이 주로 Dom-XSS의 source로 발견된다. 

window.location 혹은 location이 Source가 될 수 있을까?

window.location은, 쿼리스트링을 포함한 해당 URL전체를 나타내므로 Source로 사용될 수 있을 것 같다. 하지만 유저가 컨트롤할 수 있는 부분(주로 쿼리스트링)이 sink로 전달되어야 하므로 웹 어플리케이션 측의 소스 코드에서 그러한 부분(쿼리스트링만 잘라내서 sink로 전달한다던가 하는 부분)이 있지 않으면 발생하지 않을 수도 있겠다. 

# 예제 코드 

다음 코드는 wrap함수에 쿼리스트링을 전달하므로 XSS가 발생한다. 쿼리 스트링 `?<img src=1 onerror=alert(1)>`를 써서 확인해보면 alert함수가 실행되는 것을 볼 수 있다. 

```html
<!-- The application may be vulnerable to DOM-based cross-site scripting. Data is read from window.location and passed to the 'wrap()' function of function of JQuery.-->
<!-- window.location 소스(source)로부터의 입력이 jquery의 wrap함수로 전달될 때 XSS가 발생하는지 검증한다. -->
<html>

<head>
    <script src="jquery-1.8.2.js"></script>
</head>

<body>
    <script>
        // 일부러 취약하게 만든 코드 (? 를 없애고, URL인코딩된 파라메터를 URL디코드한다. )
        var html = decodeURI(window.location.search.replace("?", ""));

        console.log(html);
        $(document).ready(function () {
             $("p").wrap(html); 
        });

    </script>
    <p>test</p>
</body>

</html>

```


# 참고
- jquery wrap함수 사양: https://www.w3schools.com/jquery/html_wrap.asp


