---
layout: post
title: "Jekyll 서버 SEO 준비하기"
categories: [Jekyll 서버, SEO]
tags: [Jekyll 서버, SEO]
toc: true
---

# 개요
- Jekyll 서버에서 검색엔진에 노출되록 하기 위한 설정 방법을 정리해둔다.

# sitemap.xml 
- 동적으로 sitemap을 생성하도록 해두었다. 

# robots.txt 
다음과 같이 설정했다. 

```
User-agent: *
Allow: /
Sitemap: https://jaewoongmoon.github.io/sitemap.xml
```


# 참고 
- https://techlog.io/Programming/jekyll%EC%97%90%EC%84%9C-%EA%B2%80%EC%83%89%EC%97%94%EC%A7%84-%EC%B5%9C%EC%A0%81%ED%99%94%EB%A5%BC-%ED%95%98%EB%8A%94-10%EA%B0%80%EC%A7%80-%EB%B0%A9%EB%B2%95/
- 