---
layout: post
title: "MAC 관련 개념 정리"
categories: [보안일반, 암호, MAC]
tags: [보안일반, 암호, MAC]
toc: true
last_modified_at: 2024-06-26 21:00:00 +0900
---


# 개요
MAC 개념에 대해 정리해둔다. 


# MAC이란
- Message Authentication Code (메세지 인증 코드)의 약자다. 
- 메세지가 통신 중간에 변조되지 않았는지를 체크하기 위해 사용한다. 
- 좀더 어렵게 말하면 통신 데이터의 변조 유무를 탐지하여, 완전성(Integrity)를 보장하기 위해 통신 데이터로부터 생성된 고정길이의 코드(비트열)이다. 
- MAC에는 블록 암호를 사용한 CMAC(Cipher-based MAC)과 해시함수를 사용한 HMAC이 있다. 

# HMAC
- 해시함수는 통신 데이터의 변조 탐지에 유효한 기술이지만, 알고리즘이 공개되어 있기 때문에 악의적인 공격자가 데이터를 변조한 뒤에 해시값을 재계산해서 보내면 수신측에서 변조를 탐지할 수 없다는 문제가 있다. 
- 이 문제에 대처하기 위해 IPsec등에서는 HMAC (Keyed-Hashing for Message Authentication Code: 키가 추가된 해시함수)을 사용한다. 
- HMAC에서는 해시함수의 계산시에, 통신을 수행하는 양측간에 미리 공유되어 있는 비밀키의 값을 추가하는 것으로, 같은 데이터와 같은 해시 함수를 사용하더라도, 해당 통신에서 고유한 해시 값을 가지는 것이 가능해진다. 이로 인해, 악의적인 사용자가 통신 중간에서 데이터를 변조한다고 하더라도 비밀키를 알고 있지 않은 이상 수신측은 변조를 알아챌 수 있게 된다. 
- MD5를 사용한 HMAC은 HMAC-MD5, SHA-256를 사용한 HMAC은 HMAC-SHA-256 등으로 부른다. 


## HMAC을 생성하는 파이썬 코드

파이썬에서 hmac 을 생성하는 것은 아주 쉽다.

출처: https://stackoverflow.com/questions/39767297/how-to-use-sha256-hmac-in-python-code

```py
import hashlib
import hmac

# Define my and key as per question
my = "/api/embedded_dashboard?data=%7B%22dashboard%22%3A7863%2C%22embed%22%3A%22v2%22%2C%22filters%22%3A%5B%7B%22name%22%3A%22Filter1%22%2C%22value%22%3A%22value1%22%7D%2C%7B%22name%22%3A%22Filter2%22%2C%22value%22%3A%221234%22%7D%5D%7D"
key = "e179017a-62b0-4996-8a38-e91aa9f1"

# Encode as per other answers
byte_key = key.encode("UTF-8")
message = my.encode()

# Now use the hmac.new function and the hexdigest method
h = hmac.new(byte_key, message, hashlib.sha256).hexdigest()

# Print the output
print(h)
```

# MAC 구현시 암호화 순서에 대한 고찰
모바일 앱을 분석하던 중 앱의 암호화 코드에서 MAC이란 값을 구하는 부분이 있어서 관련 자료를 찾아보던 중 MAC을 구한 후에 암호화를 하는 것(MAC-then-Encrypt) 보다 평문을 암호화한 후에 MAC을 붙이는 것(Encrypt-then-MAC)이 더 좋다는 글을 발견하였다. 과연 저 말이 사실인지, 그 이유는 무엇인지에 대해 조사해보았다.  

## MAC-then-Encrypt (MtE)
- [원문 + 원문의 MAC] 을 암호화
- 이 방식을 사용하는 프로토콜 : TLS 
- 특징
1) 암호문의 무결성을 제공안함
2) 원문의 무결성 제공
3) 만약 암호문이 복호화되면 원문과 원문의 MAC 값이 드러나 버린다.
4) 원문을 통해서 MAC 과의 관계를 알 가능성이 있다. 
	
## Encrypt-and-MAC (E&M)
- [암호문 + 원문의 MAC] 
- 이 방식을 사용하는 프로토콜 : SSH
- 특징
1) 암호문의 무결성 제공 안함
2) 원문의 무결성 제공
3) MAC이 원문으로부터 만들어졌기 때문에 원문과 MAC과의 관계를 알 가능성 존재

## Encrypt-then-MAC (EtM)
- [암호문 + 암호문의 MAC] 
- 사용 프로토콜 : IPSec
- 가장 좋은 방식이다. 
- 특징
1) 암호문의 무결성을 제공
2) 원문의 무결성 제공
3) MAC이 원문과 관련이 없기 때문에, 원문과 MAC의 관계를 알 수 없다. 

## 결론
Encrypt-then-MAC 방식을 쓰자. 


# 참고 URL
- https://crypto.stackexchange.com/questions/202/should-we-mac-then-encrypt-or-encrypt-then-mac
- http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html
- https://ja.wikipedia.org/wiki/%E8%AA%8D%E8%A8%BC%E4%BB%98%E3%81%8D%E6%9A%97%E5%8F%B7
- https://medium.com/@ErikRingsmuth/encrypt-then-mac-fc5db94794a4