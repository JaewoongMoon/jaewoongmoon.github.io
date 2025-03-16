---
layout: post
title: "Docker 설치방법"
categories: [Docker, Container]
tags: [Docker, Container]
toc: true
last_modified_at: 2024-08-06 14:55:00 +0900
---

# 개요
아마존 리눅스 EC2에 도커를 설치하는 방법을 정리한다. 

# 설치하기

```sh
sudo yum install -y docker
sudo service docker start 
sudo docker info # 상태 확인 
```

# 유저를 도커 그룹에 추가하기 
- 자신이 주로 작업하는 유저를 docker 그룹에 추가한다. 
- 필요에 따라 아래 커맨드의 `ec2-user` 부분을 다른 유저명으로 바꾼후 실행한다.
- 실행한 후에는 해당 유저로 재로그인할 필요가 있다. 
- 이 부분을 실시하지 않으면 docker 실행 시에 `permission denied`에러가 발생한다. 

```sh
sudo usermod -aG docker ec2-user
```

로그인한 계정이 docker 그룹에 포함되어 있는지는 id 커맨드를 치면 확인할 수 있다. 아래는 ec2-user로 로그인한 뒤 확인해본 모습이다.

```sh
$ id
uid=1000(ec2-user) gid=1000(ec2-user) groups=1000(ec2-user),4(adm),10(wheel),190(systemd-journal),991(docker)
```


# 참고
- https://qiita.com/y-dobashi/items/e127211b32296d65803a
- https://zenn.dev/botamotch/scraps/43f6b5e560137f
- https://docs.docker.com/engine/install/linux-postinstall/