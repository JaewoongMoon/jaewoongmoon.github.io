---
layout: post
title: "Burp Academy-인증(Authentication) 취약점: Username enumeration via response timing"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, 인증취약점]
toc: true
---

# 개요
- 인증(Authentication)에 관련된 취약점이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/authentication/password-based
- 문제 주소: : https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing
- 난이도: PRACTITIONER (보통)


# 문제 설명
- 이번에는 존재하는 ID나 패스워드일 경우엔 응답 시간이 다르다는 것 같다. 

```
This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

Your credentials: wiener:peter
Candidate usernames
Candidate passwords
```

# 도전

일단 바로 ID 브루트포스해본다. 

그러자 너무 많은 로그인 시도를 했다며 30분후에 다시 시도하라는 메세지가 출력된다. 

`You have made too many incorrect login attempts. Please try again in 30 minute(s).`

![로그인실패](/images/burp-academy-authn-5-1.png)

하나 특이한 점은 8,9,10번째 요청에서는 `Invalid username or password.`라는 응답이었다는 점이다. 

![Invalid username or password](/images/burp-academy-authn-5-2.png)

Intruder에서 응답시간관련 값은 상단의 Columns 메뉴에서 Response received와 Response completed를 선택해서 추가할 수 있따. 

![Intruder 응답시간관련 설정](/images/burp-academy-authn-5-3.png)

응답시간을 비교해보면  Response received 와 Response completed 값이 확연하게 차이나는게 하나 보인다. 

![응답시간비교](/images/burp-academy-authn-5-4.png)

그러나 이 ID를 가지고 패스워드 브루트포스해도 결과는 모두 200 응답 `You have made too many incorrect login attempts. Please try again in 30 minute(s).` 이었다. 

잘 모르겠다. 정답을 보자. 

# 답을 보고 풀이 

## 악용가능한 부분(공격 포인트) 찾기 
Repeater를 사용해서 확인한다. 먼저 IP블록을 우회하는 방법을 알아보자. 

### IP블록을 우회하는 방법
`X-Forwarded-For` 헤더를 사용한다. 

블록이 걸린 상태에서 `X-Forwarded-For` 헤더를 붙여서 요청을 보내보면 다시 정상처리되는 것을 확인할 수 있다. 

IP 블록된 상태 
![IP 블록된 상태](/images/burp-academy-authn-5-5.png)

`X-Forwarded-For` 헤더를 붙여서 IP블록을 우회한 상태 
![IP블록우회](/images/burp-academy-authn-5-6.png)

### 응답시간이 다른 곳을 찾기 
그러면 응답시간이 다른 곳을 찾아본다. wiener라는 usernmae은 문제에서 주어졌으므로 존재한다는 것을 알고 있다. wiener를 username파라메터에 설정한 채로 password를 변경한다. 그러면 패스워드가 길어지면 응답 시간도 길어진다는 것을 알 수 있다. Repeater의 우측 하단에 나타나는 밀리초 정보가 응답시간이다. 

존재하는 username, 긴 패스워드일 때의 응답
![존재하는 username, 긴 패스워드일 때의 응답](/images/burp-academy-authn-5-7.png)

그러면 반대로 존재하지 않는 username일 경우엔 어떨까? 대충 만든 username으로 테스트해보면 존재하지 않는 username일 경우엔 응답시간이 짧다는 것을 알 수 있다. 이 것으로 긴 패스워드를 사용해서 username을 브루트포스해봤을 대, 응답시간이 긴 요청이 있다면 그 요청의 username이 존재하는 것이라고 판단할 수 있다. 

존재하지 않는 username, 긴 패스워드일 때의 응답
![존재하지 않는 username, 긴 패스워드일 때의 응답](/images/burp-academy-authn-5-8.png)

## 존재하는 username 찾기 
IP 블록 기능이 존재하므로 `X-Forwarded-For` 헤더도 각 요청마다 다르게 지정해주도록 Intruder에서 설정할 필요가 있다. 

Intruder의 Positions탭에서  `X-Forwarded-For`헤더와 username 파라메터를 추가(Add버튼)한다. 그리고 Attack Type은 `Pitchfork`를 선택한다. `X-Forwarded-For`헤더에 설정할 페이로드와 username에 설정할 페이로드가 서로 다른 세트이기 때문이다. Attack Type에 대해서는 [Burp Intruder Attack Types 정리]({% post_url 2023-06-07-burp-intruder-attack-types %})를 참고한다. 

![Intruder설정](/images/burp-academy-authn-5-9.png)

Payloads탭에서 Payload set 1를 다음과 같이 설정한다. (X-Forwarded-For 헤더에 설정되는 페이오드 셋이다.)

이렇게 하면 1부터 100까지 1씩 증가하면서 늘어난다. Max fraction digits는 0으로 설정해서 소수점자리는 변경이 없도록 만든다. 

![Payload set 1](/images/burp-academy-authn-5-10.png)

Payload set 2는 항상 사용해오던 Simple List를 선택하고 username 후보군을 복사해서 붙여넣기 한다. 

그리고 공격을 수행하면 wiener와 동일하게 시간이 오래걸린 username이 하나보인다! 이것이 시스템에 존재하는 username이다. 

![username 브루트포스 결과](/images/burp-academy-authn-5-11.png)

## 찾은 username의 패스워드 찾기 
그러면 이제 남은 부분은 쉽다. username을 고정하고 password부분을 브루트 포스하면 된다. `X-Forwarded-For` 헤더 부분은 그대로 두고, password를 포지션에 추가한다. 

![password 브루트포스 설정](/images/burp-academy-authn-5-12.png)


공격 결과는 다음과 같다. 302응답이 하나 보인다. 이 패스워드가 해당 username의 패스워드이다. 

![password 브루트포스 설정](/images/burp-academy-authn-5-13.png)

그러면 이제 username과 password를 알아내었으니 로그인해본다. 로그인되면 문제 풀이에 성공했다는 메세지가 출력된다. 

![password 브루트포스 설정](/images/burp-academy-authn-5-success.png)

