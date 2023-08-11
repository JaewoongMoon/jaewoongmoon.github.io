---
layout: post
title: "도커이미지에서 Dockerfile 추출하기"
categories: [프로그래밍]
tags: [프로그래밍, Docker]
toc: true
last_modified_at: 2023-08-10 14:02:00 +0900
---

# 개요 
도커이미지에서 Dockerfile 추출하기

# Docker history 커맨드로 확인하기 

다음 명령으로 대충 이미지를 만들 때 어떤 명령이 실행됐는지 알 수 있다. 

```
docker history [이미지명] 
```

혹은 명령어가 잘리는게 싫으면 --no-trunc옵션으로 실행 

```
docker history [이미지명] --no-trunc 
```

# 툴 사용
여기에 따르면 Dedokify라는 리버스 엔지니어링 툴도 있는 것 같다. (https://gcore.com/learning/reverse-engineer-docker-images-into-dockerfiles-with-dedockify/)