---
layout: post
title: "Burp Academy-안전하지 않은 역직렬화(Insecure Deserialization) 관련 취약점: Modifying serialized objects"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Insecure Deserialization]
toc: true
last_modified_at: 2024-05-01 21:00:00 +0900
---


# 개요
- 안전하지 않은 역직렬화(Insecure Deserialization) 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects
- 취약점 설명페이지: https://portswigger.net/web-security/deserialization
- 취약점 설명페이지2: https://portswigger.net/web-security/deserialization/exploiting#how-to-identify-insecure-deserialization
- 난이도: APPRENTICE (쉬움)

# 직렬화 개요 
- 직렬화(Serialization)는 데이터구조 또는 오브젝트를 순차적인 바이트 스트림으로 송수신할 수 있는 평평한(flatter) 형식으로 변환하는 과정이다. 
- 주로 타 시스템과 네트워크 상에서 데이터를 교환하기 위해 사용된다. (바이트이므로 네트워크 상에서 다루기 쉽다.)
- 역직렬화(Deserialization)은 그 반대 과정이다. 바이트를 시스템에서 이해할 수 있는 오브젝트로 변환한다. 
- 직렬화는 각 언어에서 부르는 이름이 다른 경우도 있다. Go나 Ruby에서는 마샬링(marshalling)이라 부르고, Python에서는 피클링(pickling)이라 부른다. 
- pack이나 unpack도 같은 개념이다. 

## PHP 직렬화 포맷
- PHP 직렬화 포맷은 다음과 같이 사람이 읽기 쉬운 형식이다. 
- `O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}` 
- `O:4:"User"`는 O는 오브젝트를 의미하며 4는 이름이 네글자라는 것을 의미한다. "User"는 오브젝트의 이름이다. 
- 그 뒤의 2는 두 개의 속성이 있음을 의미한다. 
- `s:4:"name"`: 첫번째 속성의 키는 네글자로 name이다. 
- `s:6:"carlos"`: 첫번째 속성의 값은 carlos이다. 
- `s:10:"isLoggedIn"`: 두번째 속성의 키는 열글자로 isLoggedIn이다. 
- `b:1`: 두번째 속성의 값은 boolean 타입으로 1(True)이다.

## Java 직렬화 포맷
- Java 직렬화 포맷은 바이너리 타입으로 좀 더 읽기 어렵다. 
- 그러나 Java 직렬화 오브젝트임을 나타내는 특징이 있다. 언제나 바이트 `ab ed` (base64 인코딩하면 `rO0`)로 시작한다는 점이다.
- Java의 `java.io.Serializable` 인터페이스를 구현한 오브젝트는 직렬화되거나 역직렬화 될 수 있다. 
- 역직렬화 할 때 Java의 `InputStream`으로부터 데이터를 읽어서 역직렬화해주는 `readObject()`함수를 사용할 수 있다. 

# 안전하지 않은 직렬화(Insecure Deserialization)란?
- 유저가 입력을 컨트롤 가능한 곳에 공격용 페이로드를 설정한 직렬화된 인풋을 입력을하는 것으로 서버측의 이상행동을 유발하는 테크닉이다. 
- 이상적으로는 유저가 입력가능한 곳에서 직렬화 오브젝트를 받으면 안된다. 


# 문제 개요
- 이 랩은 직렬화 베이스의 세션 관리 메커니즘을 사용하고 있고, 결과적으로 권한 상승 취약점이 존재한다. 
- 랩을 풀려면 세션 쿠키 안에 있는 직렬화 오브젝트를 수정해서 관리자 권한을 얻어내어 carlos유저를 삭제하면 된다. 
- wiener:peter 크레덴셜로 로그인할 수 있다. 

```
This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result. To solve the lab, edit the serialized object in the session cookie to exploit this vulnerability and gain administrative privileges. Then, delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter
```

# 도전
1. 주어진 크레덴셜로 로그인해 본다. 로그인에 성공하면 서버가 세션쿠키를 회신해주는 것을 알 수 있다. 

![](/images/burp-academy-serial-1-1.png)

2. 세션쿠키를 Base64 디코딩해본다. 그러면 다음과 같은 값인 것을 알 수 있다. PHP에서 쓰이는 직렬화 방식이다. admin 부분의 boolean 값이 0인 것이 눈에 띤다. 

`O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}`

![](/images/burp-academy-serial-1-2.png)

3. admin 부분의 boolean 값을 1로 바꾼 후에 다시 Base64 인코딩한다. 

![](/images/burp-academy-serial-1-7.png)

4. 인코딩한 값을 세션쿠키로 지정해서 요청을 보내본다. 그러면 200응답이 돌아오고 admin패널이 보이는 것을 알 수 있다. 

![](/images/burp-academy-serial-1-3.png)

5. GET /admin 으로 요청을 보내본다. 그러면 carlos유저를 삭제하는 링크가 보인다. 

![](/images/burp-academy-serial-1-4.png)

6. carlos 유저를 삭제하는 링크로 요청을 보낸다. 유저 삭제에 성공하여 302응답이 회신된다. 

![](/images/burp-academy-serial-1-5.png)

7. 문제가 풀렸다는 메세지가 출력된다. 🍟

![](/images/burp-academy-serial-1-success.png)