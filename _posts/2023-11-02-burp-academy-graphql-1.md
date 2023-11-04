---
layout: post
title: "Burp Academy-GraphQL API 관련 취약점: Exploiting NoSQL operator injection to extract unknown fields"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, SQLi, NoSQL, NoSQL injecition]
toc: true
last_modified_at: 2023-11-02 09:50:00 +0900
---


https://portswigger.net/web-security/graphql

# Instrospection 쿼리
다음 요청을 보내서 Instrospection이 동작하는지 확인할 수 있다. 

```json
#Introspection probe request

{
    "query": "{__schema{queryType{name}}}"
}
```