---
layout: post
title: "Burp Academy-인증(Authentication) 취약점: Broken brute-force protection, IP block"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, OAuth취약점]
toc: true
---

# 개요
- 인증(Authentication)에 관련된 취약점이다. 
- 취약점 설명 주소: https://portswigger.net/web-security/authentication/password-based
- 문제 주소: : https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block
- 난이도: PRACTITIONER (보통)

# 취약점 설명
- 브루트포스를 방어하기 위한 메커니즘으로 로그인 실패가 계속되면 해당 계정을 잠금하는 방법과 해당 IP를 블록하는 방법이 있다. 
- 유효한 방법이지만 구현에 따라서는 취약해질 수 있다. 
- 예를들어 어떤 시스템은 특정 로그인 실패 회수를 넘어서면 해당 IP가 블록된다고 하자. 
- 그리고 로그인이 성공하면 해당 IP의 로그인 실패 회수 카운트가 초기화된다고 하자. 
- 이러면 특정 로그인 실패 회수에 도달하기 전에 로그인 가능한 계정으로 한번씩 로그인해주는 것으로 방어 메커니즘을 우회할 수 있다. 

```
Flawed brute-force protection
It is highly likely that a brute-force attack will involve many failed guesses before the attacker successfully compromises an account. Logically, brute-force protection revolves around trying to make it as tricky as possible to automate the process and slow down the rate at which an attacker can attempt logins. The two most common ways of preventing brute-force attacks are:

Locking the account that the remote user is trying to access if they make too many failed login attempts
Blocking the remote user's IP address if they make too many login attempts in quick succession
Both approaches offer varying degrees of protection, but neither is invulnerable, especially if implemented using flawed logic.

For example, you might sometimes find that your IP is blocked if you fail to log in too many times. In some implementations, the counter for the number of failed attempts resets if the IP owner logs in successfully. This means an attacker would simply have to log in to their own account every few attempts to prevent this limit from ever being reached.

In this case, merely including your own login credentials at regular intervals throughout the wordlist is enough to render this defense virtually useless.
```

# 문제 설명
- 브루트포스 방어 메커니즘이 존재한다. 
- 로그인가능한 계정이 주어졌다. 
- 위의 최약점 설명대로 일정 횟수 시도 후에 정상적인 로그인을 시도하는 방법을 써야겠다. 

```
This lab is vulnerable due to a logic flaw in its password brute-force protection. To solve the lab, brute-force the victim's password, then log in and access their account page.

Your credentials: wiener:peter
Victim's username: carlos
Candidate passwords
```

# 도전 
## 로그인 몇 번 틀리면 블록되는지 알아내기 
일단 로그인을 몇 번 틀리면 블록되는지를 알아보자. 

처음 패스워드가 틀렸을 때는 다음과 같다. 

![패스워드가 틀릴 때](/images/burp-academy-authn-6-1.png)

이 것을 반복해본다. 3번 이상 틀렸을 때 다음과 같은 메세지가 출력되었다. 

`You have made too many incorrect login attempts. Please try again in 1 minute(s).`

![IP블록된 상태](/images/burp-academy-authn-6-2.png)

이 것으로 로그인 시도횟수는 3번을 넘기면 1분간 IP주소가 블록된다는 것을 알았다. 

## Intruder 설정

### 페이로드 세트 만들기 
3번 로그인 실패하면 블록되므로 실제로 시도가능한 횟수는 2번이다. 2번 브루트포스를 시도하고 3번째부터는 로그인가능한 크레덴셜(wiener:peter)을 넣어서 서버측의 카운트를 초기화해야 한다. 이 것을 Burp Suite에서 어떻게 실행할 수 있을까?

간단히 생각하면 Attack Type을 `Pitchfork`로 선택하고 세번째마다 wiener:peter를 시도하도록 페이로드 세트를 만들면 될 것 같다. (페이로드 세트를 ID용과 패스워드 용 두 개를 만들어야 한다.) 만드는 게 조금 귀찮긴 하다. 뭔가 더 스마트한 방법이 있을 듯도 한데...

음... 혹시 이런 경우에 쓸 수 있는 Intruder의 Payload type이 있나 찾아봤는데 딱히 없어보인다. 

https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types

그냥 만든다...

다음과 같이 만들었다. 

#### ID(username) 리스트

```
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
carlos
carlos
wiener
```

#### 패스워드 리스트
```
123456
password
peter
12345678
qwerty
peter
123456789
12345
peter
1234
111111
peter
1234567
dragon
peter
123123
baseball
peter
abc123
football
peter
monkey
letmein
peter
shadow
master
peter
666666
qwertyuiop
peter
123321
mustang
peter
1234567890
michael
peter
654321
superman
peter
1qaz2wsx
7777777
peter
121212
000000
peter
qazwsx
123qwe
peter
killer
trustno1
peter
jordan
jennifer
peter
zxcvbnm
asdfgh
peter
hunter
buster
peter
soccer
harley
peter
batman
andrew
peter
tigger
sunshine
peter
iloveyou
2000
peter
charlie
robert
peter
thomas
hockey
peter
ranger
daniel
peter
starwars
klaster
peter
112233
george
peter
computer
michelle
peter
jessica
pepper
peter
1111
zxcvbn
peter
555555
11111111
peter
131313
freedom
peter
777777
pass
peter
maggie
159753
peter
aaaaaa
ginger
peter
princess
joshua
peter
cheese
amanda
peter
summer
love
peter
ashley
nicole
peter
chelsea
biteme
peter
matthew
access
peter
yankees
987654321
peter
dallas
austin
peter
thunder
taylor
peter
matrix
mobilemail
peter
mom
monitor
peter
monitoring
montana
peter
moon
moscow
peter
```

### 페이로드 포인트
username과 password 파라메터를 페이로드 포인트로 추가한다. 

![페이로드 포인트 추가](/images/burp-academy-authn-6-3.png)


### 페이로드 타입 
페이로드 타입은 Simple list를 선택한다. 그리고 위에서 만든 페이로드 세트 1과 페이로드 세트 2를 설정한다. 

![페이로드 세트 설정](/images/burp-academy-authn-6-4.png)


### 동시 요청 횟수 제한 
Burp Suite Professional을 사용하고 있다면 동시 요청회수를 1로 제한해야 한다. 기본이 10으로 되어 있어 동시에 10건을 전송하면 위의 초기화 전략이 제대로 동작하지 않을 것이다. Resource Pool 탭에서 Create new resource pool을 선택하고 Maximum concurrent requests를 1로 입력한다. 

![동시요청회수 제한](/images/burp-academy-authn-6-5.png)

## 공격 시도 
그리고 공격을 시도해보면 carlos 계정에서 특정 패스워드일 때 HTTP 응답코드가 302인 것을 발견할 수 있다. 이 것이 carlos계정의 패스워드이다. 

![302응답](/images/burp-academy-authn-6-6.png)

이 패스워드로 로그인하면 문제풀이에 성공했다는 메세지가 출력된다. 

![풀이성공](/images/burp-academy-authn-6-success.png)

