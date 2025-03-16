---
layout: post
title: "Burp Academy-레이스컨디션 관련 취약점: Single-endpoint race conditions"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, 레이스컨디션, Race Condition]
toc: true
last_modified_at: 2023-09-12 14:33:00 +0900
---

# 개요
- 새로 추가된 레이스 컨디션 관련 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/race-conditions/lab-race-conditions-single-endpoint
- 취약점 설명페이지: https://portswigger.net/web-security/race-conditions#single-endpoint-race-conditions
- 난이도: PRACTITIONER (보통)

# 문제 설명 
- 메일 주소 carlos@ginandjuice.shop에는 이 사이트의 관리자로 초대하는 요청을 전송된 상태이지만 아직 계정이 만들어지지는 않았다. 
- 따라서 **이 메일 주소를 사용한다고 인증할 수 있으면 관리자 권한으로 계정을 만들 수 있다.**
- 이 랩을 풀기 위해서는 먼저 임의의 이메일 주소를 등록할 수 있는 레이스 컨디션이 가능한 엔드포인트를 찾아야 한다. 
- 그리고 이메일 주소를  carlos@ginandjuice.shop.로 변경한다. 
- 그리고  @exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net 메일주소로 보낸 메일은 모두 볼 수 있게 되어 있다. 

```
This lab's email change feature contains a race condition that enables you to associate an arbitrary email address with your account.

Someone with the address carlos@ginandjuice.shop has a pending invite to be an administrator for the site, but they have not yet created an account. Therefore, any user who successfully claims this address will automatically inherit admin privileges.

To solve the lab:

Identify a race condition that lets you claim an arbitrary email address.
Change your email address to carlos@ginandjuice.shop.
Access the admin panel.
Delete the user carlos
You can log in to your own account with the following credentials: wiener:peter.

You also have access to an email client, where you can view all emails sent to @exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net addresses.

Note
Solving this lab requires Burp Suite 2023.9 or higher.
```

# 문제 살펴보기 & 풀이 방법 생각해보기 

문제에서 주어지는 wiener 계정으로 로그인해보면 다음과 같이 이메일을 변경할 수 있는 기능이 있다. 

![이메일 변경 기능](/images/burp-academy-race-condition-4-1.png)

이메일 클라이언트 기능은 다음과 같다. xxx@exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net 로 들어오은 메일은 모두 확인할 수 있다. 

![이메일 클라이언트 기능](/images/burp-academy-race-condition-4-2.png)

아마 단순히 wiener 계정의 메일 주소 `wiener@exploit-0a44000103087c9480b30c5401ce00da.exploit-server.net` 를 `carlos@ginandjuice.shop`로 변경하는 것은 아닐 것이다. 

그래도 일단 한번 시도해본다. 그러면 다음과 같이 `carlos@ginandjuice.shop`에 도착한 confirm 링크를 클릭하라는 안내가 나온다. 

![이메일 변경하기](/images/burp-academy-race-condition-4-3.png)

`carlos@ginandjuice.shop`메일 주소로 로그인해서 내용을 확인할 수는 없으니 계정을 만들 수 없다. 해당 메일 주소로 메일이 전달되더라도 그 내용을 볼 수 있어야 풀 수 있다. 방법을 생각해본다. 

레이스 컨디션으로 서버가 confirm링크를 `carlos@ginandjuice.shop`로 보내면서 동시에 그 내용을 `wiener@exploit-0a44000103087c9480b30c5401ce00da.exploit-server.net`로 보내도록 만들면 될 것같다. 그렇게 되면 공격자는 도착한 메일 내용을 확인해서 confirm링크에 접근, 이메일 주소 변경을 할 수 있을 것이다. 이메일 주소가 carlos@ginandjuice.shop가 되면 이 메일 주소에는 관리자권한으로 초대가 보내져 있으므로 wiener유저도 관리자 권한으로 사이트에 접근할 수 있을 것이다. 

# 풀이 시도
## 이메일 주소를 변경하는 요청을 동시에 보내기 
이메일 주소를 `wiener@exploit-0a44000103087c9480b30c5401ce00da.exploit-server.net`로 변경하는 요청과 `carlos@ginandjuice.shop`로 변경하는 요청을 Single Packet Attack을 사용해서 동시에 보내보자. 운이 좋으면 `carlos@ginandjuice.shop`로 보내는 메일 내용이 `wiener@exploit-0a44000103087c9480b30c5401ce00da.exploit-server.net`로 전달되어 내용을 확인할 수 있을 지도 모른다. 

![Single Packet Attack](/images/burp-academy-race-condition-4-7.png)

그리고 이메일 클라이언트를 확인해보면 다음과 같이 메일이 도착한 것을 볼 수 있다. To에는 `wiener@exploit-0a44000103087c9480b30c5401ce00da.exploit-server.net`가 적혀있으나 Body 부분의 내용은 `carlos@ginandjuice.shop`로 보내는 내용이다! 레이스 컨디션 공격에 성공한 것이다. 

![이메일 전송결과](/images/burp-academy-race-condition-4-4.png)

메일의 confirm 링크를 클릭하고 다시 사이트로 돌아가서 페이지를 새로고침해본다. 그러면 wiener 계정의 이메일이 업데이트되었고, Admin Panel이 활성화되어 있는 것을 볼 수 있다. 

![이메일 업데이트 결과](/images/burp-academy-race-condition-4-5.png)

Admin Panel로 들어가서 carlos 유저를 삭제한다. 

![Admin Panel](/images/burp-academy-race-condition-4-6.png)

그러면 문제 풀이에 성공했다는 메세지가 나타난다. 

![문제 풀이 성공](/images/burp-academy-race-condition-4-success.png)

# 감상
- 이번 취약점은 Single-endpoint 레이스 컨디션 문제였다. 
- 어떤 중요한 처리를 하는 시스템의 Endpoint에 레이스 컨디션 취약점이 있으면 관리자 권한 탈취로까지 이어질 수 있다는 것을 확인했다.
- 이메일 주소 업데이트 뿐 아니라 패스워드 변경과 같은 것도 마찬가지다. 특정 계정의 새로운 패스워드를 이메일로 통지하는 시스템이 있다고 할 때, 이 새로운 패스워드를 공격자 자신의 이메일로 보내도록 할 수 있다면 해당 계정을 탈취할 수 있을 것이다. 
- 중요 처리에는 레이스 컨디션 취약점이 없도록 구현하는 것이 좋다. 