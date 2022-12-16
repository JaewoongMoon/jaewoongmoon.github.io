---
layout: post
title: "Docker Desktop"
categories: [프로그래밍]
tags: [프로그래밍, 컨테이너, Docker, DockerDesktop]
---

# Docker Desktop 구동시 필요하지 않은 컨테이너는 자동으로 구동되지 않도록 하기 
- Docker Desktop 구동시 자동으로 함께 시작되는 컨테이너들이 있다. 
- 자동으로 시작되지 않도록 하고 싶을 때 다음 방법을 참고한다 .

## STEP 1. Docker 옵션을 변경 
- 이것은 Docker 컨테이너의 restart 옵션이 켜져있어서 되어 있어서 그렇다.
- restart에 사용가능한 설정값은 여기를 참고한다. (https://docs.docker.jp/engine/reference/run.html#restart-policies-restart)
- docker-compose.yml 파일에서는 `restart: "no"` 같은 식으로 no에 쌍따옴표를 붙여야 한다. no가 특별한 의미를 가지기 때문이다. (ye는 True, no는 False)

## STEP 2. 변경된 옵션을 적용
- 해당 프로젝트에서 docker-compose up -d 를 실행해서 변경된 설정이 적용된 이미지를 다시 만든다. 

## STEP 3. Docker Desktop 을 재시작 
- Docker Desktop 을 재시작한다. 
- 그러면 더 이상 자동으로 컨테이너가 시작되지 않는 것을 확인할 수 있다. 
