---
layout: post
title: "Burp Academy-레이스컨디션 관련 취약점: Limit overrun race conditions"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, 레이스컨디션, Race Condition]
toc: true
last_modified_at: 2023-09-01 10:33:00 +0900
---

# 개요
- 새로 추가된 레이스 컨디션 관련 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun
- 취약점 설명페이지: https://portswigger.net/web-security/race-conditions#limit-overrun-race-conditions
- 난이도: APPRENTICE (쉬움)

# 레이스 컨디션(Race Condition)이란 
- 레이스컨디션은 비즈니스 로직 흐름과 관련된 취약점으로, 웹 사이트측에서 동시 요청을 처리할 때 적절한 세이프가드가 없을 때 발생한다. 
- 이는 여러개의 스레드가 동일한 데이터를 동일한 시간에 접근하려고 할 때 일어날 수 있으며(충돌상황), 이로 인해 의도되지 않은 동작이 수행될 수 있다. 
- 공격자는 여러개의 요청을 특정 기간 사이에 동시에 보냄으로써 의도적으로 충돌(레이스 컨디션)을 일으킨다. 

![](/images/burp-academy-race-condition-0-1.png)
출처: https://portswigger.net/web-security/race-conditions#limit-overrun-race-conditions

- 충돌을 일으킬 수 있는 기간은 "race window"라고 부른다. 

## 리미트 오버런(Limit Overrun)이란
- 어플리케이션에서 설정된 실행 횟수 제한(Limit)를 넘어서 어떤 작업을 수행하게 하는(Overrun) 공격 기법이다. 
- 레이스 컨디션에 속하는 공격중에서 가장 잘 알려진 타입이다. 

예를 들어, 상품구입시에 한번만 사용가능한 프로모션 코드(쿠폰)을 입력할 수 있는 온라인 스토어를 상상해보자. 가격을 할인하기 위해 다음과 같은 단계를 거칠 것으로 생각할 수 있다. 

1. 이 코드가 사용된 적이 한번도 없었는지 체크한다. 
2. 전체 주문금액에 할인율을 적용한다. 
3. 쿠폰을 사용했다는 것을 저장하기 위해 데이터베이스의 레코드를 업데이트한다. 

만약 나중에 이 코드를 재사용하기 위해 입력해보면 다음과 같이 Invalid code가 출력될 것이다. 

![](/images/race-conditions-discount-code-normal.png)

그리고 쿠폰 적용을 거의 동일한 타이밍에 요청했다고 생각해보자. 한쪽 요청에서 위의 세 과정의 진행이 완료되기 전에 다른 요청의 처리가 시작되면 쿠폰을 여러번 사용할 수 있게 된다! 

![](/images/race-conditions-discount-code-race.png)

리미트 오버런은 다양한 베리에이션이 존재한다. 다음과 같은 경우를 생각할 수 있다. 
- 일회용인 기프트권을 여러번 사용한다. 
- 상품에 대한 평점을 여러번 남긴다. 
- 계좌의 잔고를 넘어선 금액을 인출 혹은 송금한다. 
- 캡챠(CAPTCHA)를 재사용한다. 
- 브루트포스를 방어하기 위한 횟수 제한을 우회한다. 

리미트 오버런은 "time-of-check to time-of-use" (TOCTOU) 이라고 알려진 결점의 서브타입이기도 하다. 


## Burp Repeater를 이용해서 리미트 오버런을 찾고 exploit하는 방법

1. 한번만 사용가능한, 혹은 횟수 제한이 있으면서 어떤 세큐리티 임팩트 혹은 유저에게 유리한 목적으로 사용할 수 있는 엔드포인트를 찾는다. 

2. 이 엔드포인트에 동일한 요청을 여러번 보내서 리미트 제한을 넘어설 수 있는지 결과를 체크한다. 

이 때, 가장 어려운 것이 HTTP 요청이 서버에 동시에 도달하도록 하는 부분이다. 이 타이밍은 밀리초 이내, 혹은 더 짧아질 수도 있다. 요청들을 동시에 보냈다고 하더라도 네트워크에는 요청이 서버에 도착하는 시간에 영향을 주는 통제할 수 없는, 그리고 예측할 수 없는 여러 변수들이 존재한다. 이 것을 네트워크 지터(jitter)라고 부른다. 

![](/images/race-conditions-basic.png)

Burp Suite 2023.9 버전에서부터 Burp Repeater에서 여러개의 요청을 그룹으로 묶어서, 요청을 동시에 보낼 수 있는 기능이 추가되었다. 이 기능을 이용해서 네트워크 지터를 효과적으로 없앨 수 있다. 즉, 요청이 서버에 동시에 도달하도록 만들 수 있다. 

single-packet attack은 하나의 TCP 패킷에 20-30개의 요청을 동시에 포함해서 보내는 것으로 네트워크 지터의 영향을 완전히 무효화한다. 

![](/images/race-conditions-single-packet-attack.png)

# 랩 설명
- 이 랩에는 상품을 적정 가격이 아닌 다른 가격으로 구매할 수 있는 레이스 컨디션 취약점 있다. 
- Lightweight L33t Leather Jacket 를 구매하는 랩이 풀린다. 
- wiener:peter 로 로그인할 수 있다. 
- 이 랩을 푸는데는 Burp Suite 버전 2023.9이상이 필요하다. 

```
This lab's purchasing flow contains a race condition that enables you to purchase items for an unintended price.

To solve the lab, successfully purchase a Lightweight L33t Leather Jacket.

You can log in to your account with the following credentials: wiener:peter.

Note
Solving this lab requires Burp Suite 2023.9 or higher.
```

# 도전
## 관찰
- 사야하는 재킷의 가격이 1337달러로 비싸다. 

![상품가격확인](/images/burp-academy-race-condition-1-1.png)

그리고 잔고는 50달러 밖에 없다. 

![잔고확인](/images/burp-academy-race-condition-1-2.png)

- 20%세일된 가격으로 살 수 있는 `PROMO20`라는 쿠폰 코드를 알려주고 있다. 아마 이 코드는 일회용일텐데, 동시에 여러개의 요청을 보내면 추가로 할인이 될 것으로 예상된다. 
- 1337달러의 상품을 할인을 계속해서 50달러 이하로 만들어보자. 


## 레이스 컨디션 가능한 곳 찾기 
- 여러 요청을 그룹으로 묶은 뒤 "Single-packet attack" 을 수행할 수 있다. (Send 셀렉트박스에서 Send Group in parallel (single packet attack) 을 선택한다.)
- 쿠폰 적용하는 요청이 레이스 컨디션이 되는 것을 확인할 수 있었다. 

![](/images/burp-academy-race-condition-1-3.png)

![](/images/burp-academy-race-condition-1-4.png)

```http
POST /cart/coupon HTTP/2
Host: 0aef00fd0340b8968315101100090090.web-security-academy.net
Cookie: session=HFLp5UN41E0NpruM7ySorUcjTDcGwXS1
Content-Length: 52
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0aef00fd0340b8968315101100090090.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0aef00fd0340b8968315101100090090.web-security-academy.net/cart
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

csrf=CVwhMdoY1iM8W1qsFbR2Mu0ACJg3fp9w&coupon=PROMO20
```

쿠폰이 적용되면 다음과 같은 응답이 돌아온다. 

```http
HTTP/2 302 Found
Location: /cart
X-Frame-Options: SAMEORIGIN
Content-Length: 14

Coupon applied
```



만약 서버측에서 쿠폰이 이미 사용처리된 후라면 다음과 같은 응답이 돌아온다. 

```http
HTTP/2 302 Found
Location: /cart?couponError=COUPON_ALREADY_APPLIED&coupon=PROMO20
X-Frame-Options: SAMEORIGIN
Content-Length: 22

Coupon already applied
```

테스트해보니 쿠폰이 두번이상은 적용이 안된다. 뭔가 다른 방법이 있는건가? 생각해보자.. 

# 풀이 
모르겠다. 답을 본다. 답을 보니 결국 위에서 한 과정이 옳았다. 다만 레이스컨디션이라서 그 때그때 서버의 처리속도에 따라 달라진다. 50달러 이하로 내려가지 않으면 쿠폰을 삭제하고 다시 시도하면 된다. 14번만에 성공했다. 
다음과 같이 약20여개의 요청을 그룹화해서 병렬로 보냈다. 

![병렬로 보내는 모습](/images/burp-academy-race-condition-1-6.png)

중복세일에 성공해서 30달러까지 깍은 모습이다. 

![중복세일에 성공해서 30달러까지 깍은 모습](/images/burp-academy-race-condition-1-5.png)

구매를 시도하면 문제풀이에 성공했다는 메세지가 표시된다.

![풀이 성공](/images/burp-academy-race-condition-1-success.png)