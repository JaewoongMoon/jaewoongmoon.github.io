---
layout: post
title: "kubernetes 정리"
categories: [프로그래밍]
tags: [프로그래밍, kubernetes]
---

# 기본 개념 
## Kubernetes
- 복수의 컨테이너를 관리해주는 오케스트레이션 툴

## Node
- 실제로 콘테이너가 동작하는 서버 

## Cluster
- 복수의 노드를 묶어서 클러스터로 관리한다.  

## Pod
- 복수의 콘테이너를 묶어서 Pod라는 단위로 관리한다. 
- 예를들어, 웹 서버용 컨테이너와 프록시 서버용 컨테이너를 묶어서 하나의 pod로 관리한다. 
- Node 보다 작은 단위이다. (하나의 pod가 복수의 Node에 포함되는 경우는 없다.) 

## Service
Kubernetes 에서 서비스란 네트워크를 정의하는 녀석이다. 

한편, Ingress 라는 Pod로의 통신을 제어하는 기능이 있다. 
Ingress 는 kubernetes 를 동작하는 환경에 따라 동작이 다르다. 예를들어 GCP에서는 HTTP 로드 밸런서가 사용된다. 


