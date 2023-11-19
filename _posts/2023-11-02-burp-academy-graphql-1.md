---
layout: post
title: "Burp Academy-GraphQL API 관련 취약점: Accessing private GraphQL posts"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, GraphQL]
toc: true
last_modified_at: 2023-11-07 09:50:00 +0900
---


# 개요
- GraphQL 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts
- 취약점 설명페이지: https://portswigger.net/web-security/graphql
- 난이도: APPRENTICE (쉬움)

# GraphQL 취약점 참고 
## Instrospection 쿼리
다음 요청을 보내서 Instrospection이 동작하는지 확인할 수 있다. 

```json
#Introspection probe request

{
    "query": "{__schema{queryType{name}}}"
}
```

# 문제 개요

- 이 랩에 있는 블로그 페이지중에는 시크릿 패스워드가 적혀잇는 숨겨진 블로그 포스트가 있다. 
- 이 블로그 포스트에서 얻어낸 패스워드를 제출하면 문제가 풀린다. 
- InQL Burp 확장프로그램을 사용하는 것을 추천한다. 

```
The blog page for this lab contains a hidden blog post that has a secret password. To solve the lab, find the hidden blog post and enter the password.

We recommend that you install the InQL extension before attempting this lab. InQL makes it easier to modify GraphQL queries in Repeater, and enables you to scan the API schema.

For more information on using InQL, see Working with GraphQL in Burp Suite.
```

# 풀이
## InQL 스캔 
1. BAppStore에서 InQL을 설치한다. 

![InQL설치](/images/burp-academy-graphql-install-inql.png)

2. 설치가 완료되면 Burp Suite에 새로운 InQL탭이 보인다. 그리고 Burp Proxy탭을 보면 GraphQL 엔드포인트가 보인다. 이 엔드포인트를 타겟으로 스캔을 준비한다. 

![스캔 준비](/images/burp-academy-graphql-1-1.png)

3. 스캔 결과. Introspection 쿼리 수행 결과가 잘 정리되어 보여진다. 

getAllBlogPosts 쿼리나 getBlogPost쿼리를 사용할 수 있는 것을 알 수 있다. 

![스캔 결과](/images/burp-academy-graphql-1-2.png)


## 모든 블로그 포스트 정보 얻어내기

4. getAllBlogPosts쿼리를 사용하여 모든 블로그 포스트 정보를 얻어내 본다. 

```gql
query {
    getAllBlogPosts {
        author
        date # Timestamp scalar
        id
        image
        isPrivate
        paragraphs
        postPassword
        summary
        title
    }
}
```

서버의 응답을 보면 isPrivate 이 false인 (공개포스트인) 포스트만 보여주는 것을 알 수 있다. isPrivatre이 true인 글은 응답에 포함하지 않도록 서버측에서 제어하고 있는 것으로 보인다.  

![모든 블로그 포스트 글 보기](/images/burp-academy-graphql-1-3.png)


5. 그런데 목록을 잘 보면 id가 1,2,4,5인 포스트는 있는데 3인 포스트는 없는 것을 알 수 있다. 수상한 냄새가 난다. getBlogPost쿼리를 사용해서 id가 3인 포스트를 직접 쿼리해본다. 그러면 서버측 응답에서 이 포스트가 비밀 포스트인 것을 알 수 있다. 패스워드도 포함되어 있다. 

![id가3인글 포스트 보기](/images/burp-academy-graphql-1-4.png)

6. 이 패스워드를 제출하면 문제가 풀린다. 

![풀이 성공](/images/burp-academy-graphql-1-success.png)

# 참고 
- https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/working-with-graphql