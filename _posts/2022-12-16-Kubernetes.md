---
layout: post
title: "Kubernetes 정리"
categories: [프로그래밍]
tags: [프로그래밍, 컨테이너, Docker, Kubernetes]
---

# Kubernetes 개요
- 컨테이너화된 애플리케이션의 자동 디플로이, 스케일링 등을 제공하는 오픈소스 관리시스템 (위키피디아)
- 즉, 오케스트레이션 개념이다. 
- 관리해야할 컨테이너가 많아지면, 자연스럽게 컨테이너를 관리해야 할 필요가 생긴다. 
- 컨테이너를 관리해주는 SW는 쿠버네티스 외에도 도커 스웜등도 있다. 
- 그러나 최근에는 쿠버네티스가 가장 인기가 있는 것 같다. 
- 구글에서 만들어졌고, 15년이상 구글 내부에서 개선된 후, 2014년에 오픈소스화 되었다. 
- 

# 오케스트레이션 기능
- 디플로이: 다양한 버전의 컨테이너를 배포 가능
- 스케일링: 어떤 머신에서 동작시킬 것인가
- 오토 스케일링: 컨테이너 수 증가, 머신수 증가
- 네트워크: 컨테이너간 로드 밸런싱 등
- 리소스 매니지먼트: 환경별 리미트 제한 등
- 보안: 네트워크 폴리시, 리소스에 접근 권한 등

# 구성요소
![쿠버네티스 구성요소](/images/components-of-kubernetes.svg)

## Control Plane
전체를 컨트롤 해주는 녀석이다. 다음과 같은 컴포넌트로 구성되어 있다. 
1. kube-apiservser
- 컨트롤 플레인의 프론트엔드 
- 쿠버네티스 API를 노출한다. 
- 구성도에는 api 로 표기

2. etcd 
- 모든 클러스터 데이터를 담는 쿠버네티스 뒷단의 저장소로 사용되는 일관성·고가용성 키-값 저장소. 데이터베이스.

3. kube-scheduler
- 리소스 감시
- 노드가 배정되지 않은 새로 생성된 파드를 감지한다. 
- 작업을 실행할 노드를 선택한다. 
- 구성도에는 sched 로 표기

4. kube-controler-manager
다음과 같은 컨트롤러 기능이 있다. 
- 노드 컨트롤러: 노드가 다운되었을 때 통지와 대응에 관한 책임울 가진다. 
- 잡 컨트롤러: 일회성 작업을 나타내는 잡 오브젝트를 감시한 다음, 해당 작업을 완료할 때까지 동작하는 파드를 생성한다.
- 엔드포인트 컨트롤러: 엔드포인트 오브젝트를 채운다(즉, 서비스와 파드를 연결시킨다.)
- 서비스 어카운트 & 토큰 컨트롤러: 새로운 네임스페이스에 대한 기본 계정과 API 접근 토큰을 생성한다.
- 구성도에는 c-m 으로 표기 

5. cloud-controller-manager
- 외부와 통신하기 위한 모듈
- 로컬환경에서는 필요없음. 
- 구성도에는 c-c-m 으로 표기 

## Worker Node
워커 노드는 애플리케이션의 구성요소인 파드를 호스트한다.
1. kuberlet
- 클러스터의 각 노드에서 실행되는 에이전트
- Kubelet은 파드에서 컨테이너가 확실하게 동작하도록 관리한다.

2. kube-proxy
- 클러스터의 각 노드에서 실행되는 네트워크 프록시
- 노드의 네트워크 규칙을 유지 관리한다. 
- 구성도에는 k-proxy 로 표기 


## Kubernetes Cluster
Control Plane 과 Worker Node를 합쳐서 클러스터로 부른다. 

# 참고
- 쿠버네티스란 (일본어): https://kubernetes.io/ja/docs/concepts/overview/what-is-kubernetes/ 
- 컴포넌트에 대허서: https://kubernetes.io/ko/docs/concepts/overview/components/

# 쿠버네티스 사용하기
- Docker Desktop 설정에서 Kubernetes 기능을 유효화한다. 
- Settings > Kubernetes > Enable Kubernetes 를 체크
![쿠버네티스 사용 설정](/images/docker-desktop-enable-kuburnetes.png)


# kubectl 사용
- "쿠베 컨트롤" 이라고 부른다 .
- 엔지니어가 사용하는 커맨드 라인 툴이다. 
- 커맨드를 입력하면 kube-apiserver 에게 HTTP 요청을 보내는 방식이다. 

## 설치 
- 아래 링크에서 최신버전을 다운로드 받는다.
- https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/
- kubectl.ext 가 다운로드 된다. PATH로 등록한 폴더에 복사한다. 
- ex) C:\Users\{유저명}\bin 등 
- DockerDesktop 에서 유효화한 kubernetes 버전과 kubectl의 버전이 일치할 필요가 있다.
- 둘다 최신버전으로 설치하면 될 것 같다. 
- kubectl의 버전은 다음 명령어를 실행해서 확인한다. 
- 2022년 12월 16일 현재, 최신버전은 v1.25.2 이다. 
```sh
kubectl version --client --short
```

## kubectl 설정
- kubeconfig 를 설정한다. 
- 기본적으로는 $HOME/.kube/config 에 설정되어 있다. 