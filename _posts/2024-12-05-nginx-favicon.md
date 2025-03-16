---
layout: post
title: "Nginx 서버에 favicon 설정하는 법"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Dom 관련 취약점, XSS]
toc: true
last_modified_at: 2024-12-05 09:33:00 +0900
---


# 개요
Nginx 서버에 favicon을 설정하는 방법을 정리해둔다. 

# 특정 위치로 지정하기

다음과 같이 지정할 수 있다. 

```sh
server {
    location /favicon.ico {
        alias /usr/share/nginx/html/favicon.ico;
    }
}
```


# 억세스로그 제어

favicon 에의 억세스 로그를 남기고 싶지 않다면 다음 설정을 추가해준다. 

```sh
server {
    location /favicon.ico {
        access_log off;
        return 200;
    }
}
```

# 참고 
- https://tech.withsin.net/2017/12/08/nginx-favicon-accesslog/