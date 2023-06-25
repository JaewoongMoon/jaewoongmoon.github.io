---
layout: post
title: "Burp Academy-인증(Authentication) 취약점: Username enumeration via subtly different responses"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, 인증취약점]
toc: true
---

# 개요
- 인증(Authentication)에 관련된 취약점이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/authentication/password-based
- 문제 주소: : https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses
- 난이도: PRACTITIONER (보통)

# 문제 설명
- 저번 브루트포스 문제와 비슷하지만 조금더 어려워졌다. (응답이 아주 살짝 다르다는 것 같다. )

```
This lab is subtly vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

Candidate usernames
Candidate passwords
To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.
```

# 도전 
## ID브루트포스 
먼저 ID를 브루트포스해보자. 로그인 요청을 캡쳐해서 Intruder로 보낸다. (Ctrl + I)

```http 
POST /login HTTP/1.1
Host: 0af600fa04d506f38294512e00e200d8.web-security-academy.net
Cookie: session=iWmwSPTBR8nbrbQcgUL5ahr6RLTnfOJ6
Content-Length: 23
Pragma: no-cache
Cache-Control: no-cache
Sec-Ch-Ua: "Google Chrome";v="113", "Chromium";v="113", "Not-A.Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Origin: https://0af600fa04d506f38294512e00e200d8.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0af600fa04d506f38294512e00e200d8.web-security-academy.net/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7
Connection: close

username=ee&password=123456
```

이 랩에서 ID로 사용되는 것을 username 파라메터다. username 파라메터를 페이로드로 선택하고, 후보군 username목록을 페이로드로 붙여넣기해서 공격을 시작한다. 

![username파라메터](/images/burp-academy-authn-4-1.png)

결과를 확인해보면... 존재하는 username일 경우엔 뭔가 다른 응답일 것이다. 음... 잘모르겠다. 

## 패스워드 브루트포스
이번에는 username을 calros로 고정하고 password를 브루트포트해본다. 그리고 응답을 비교해본다. 존재하는 패스워드면 뭔가 응답이 다를 것이다. 

### 차이점 발견 
엇. 뭔가 찾은 거 같다. 유저이름이 mosrow 일때만 응답에 `<!-- -->`가 포함되어 있다! 

![username파라메터](/images/burp-academy-authn-4-2.png)

혹시 다른 패스워드일때도 이런 응답이 있었나 찾아보자. 이 것을 쉽게 찾기 위해서 Intruder의 Grep 기능을 사용한다. Intruder탭에서 Settings > Grep - Match 에서 `<!-- -->`를 추가하고 다시 Results 탭을 본다. 

![Grep-Match ](/images/burp-academy-authn-4-3.png)

그러면 다음과 같이 `<!---->`탭이 추가된 것을 볼 수 있다. HTTP응답에 이 주석이 보이는 응답을 목록에서 1로 표시된다. 123456, password, 12345678 등의 패스워드였을 때 이 주석이 보였다. 

![Grep-Match 결과](/images/burp-academy-authn-4-4.png)


## ID브루트포스에서도 차이점 발견
ID 브루트포스했을 때도 혹시 이 주석이 보이는 부분이 있었을까? 확인해보니 있다. 다음과 같았다. carlos, test, info 등의 계정에서 주석이 발견되었다. 

![ID브루트포스Grep-Match결과](/images/burp-academy-authn-4-5.png)


## 다음 단계는?
자, 특정 ID이거나 특정 패스워드일 때 응답이 다르다는 것을 발견했다. 그러면 다음 단계는 어떻게 해야할까? 

일단 주석이 발견된 파라메터는 시스템에 존재하는 값이라고 가정해보자. 즉, 위의 과정에서 확인한 carlos, test, info 계정과 123456, password, 12345678 패스워드는 존재하는 값이라고 가정한다. 

음.. 근데 뭔가 이상하다. ID후보군과 패스워드 후보군중에 어떤 값이 시스템에 존재한다면 존재하는 유저를 모든 패스워드로 시도했을 때 어느 패스워드는 성공했어야 한다. 

모르겠다. 답을 보자. 

# 답을 보고 풀이 
아아 알았다. 특정 ID일 때만 에러 메세지에 점(.)이 없다! `<!---->` 주석은 뭐였는지 모르겠다. 아마 함정인 것 같다. 

![특정 ID일 때만 다른 결과](/images/burp-academy-authn-4-7.png)

ID를 알았으니 ID를 고정하고 패스워드 브루트포스해본다. 특정 패스워드일때만 302응답이 돌아온다. 

![패스워드 브루트 포스](/images/burp-academy-authn-4-8.png)

알아낸 ID와 패스워드로 로그인하면 문제가 풀린다. 

![성공](/images/burp-academy-authn-4-success.png)


