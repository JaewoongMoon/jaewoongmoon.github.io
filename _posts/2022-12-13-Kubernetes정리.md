---
layout: post
title: "kubernetes 정리"
categories: [프로그래밍]
tags: [프로그래밍, kubernetes]
toc: true
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

## Data Plane 
Pod가 움직이는 영역 

### Worker Node
워커 노드는 애플리케이션의 구성요소인 파드를 호스트한다.
1. kuberlet
- 클러스터의 각 노드에서 실행되는 에이전트
- Kubelet은 파드에서 컨테이너가 확실하게 동작하도록 관리한다.
- 컨트롤 플레인의 API서버와 통신한다. 

2. kube-proxy
- 클러스터의 각 노드에서 실행되는 네트워크 프록시
- 노드의 네트워크 규칙을 유지 관리한다. 
- 구성도에는 k-proxy 로 표기 


## Kubernetes Cluster
Control Plane 과 Worker Node를 합쳐서 클러스터로 부른다. 

# Docker Desktop에서 쿠버네티스 사용설정하기
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
- kubectl.exe 가 다운로드 된다. PATH로 등록한 폴더에 복사한다. 
- ex) C:\Users\{유저명}\bin 등 
- DockerDesktop 에서 유효화한 kubernetes 버전과 kubectl의 버전이 일치할 필요가 있다.
- 둘다 최신버전으로 설치하면 될 것 같다. 
- kubectl의 버전은 다음 명령어를 실행해서 확인한다. 
- 2022년 12월 16일 현재, 최신버전은 v1.25.2 이다. 
```sh
kubectl version --client --short
```

## kubectl 설정
- kubeconfig 라는 설정이 있다. 
- 기본적으로는 $HOME/.kube/config 가 설정파일이다. 
- 크게 clusters, contexts, users 의 세 부분을 설정한다. 
- `kubectl config current-context` 명령으로 현재 컨텍스트를 확인할 수 있다. 


## 구문 
kubectl [command] [TYPE] [NAME]
- command: 실행하고 싶은 조작 (get, create, patch, delete)
- TYPE: pod, node, service, deployment...
- NAME: 릴소스명
- flags: 옵션의 flag --kubeconfig 등

## 리소스 타입
`kubectl api-resources` : 리소스 목록을 표시하는 커맨드

## 리소스 생성
`kubectl create -f [pod 파일명].yaml`

## 리소스 삭제
`kubectl delete -f [pod 파일명].yaml`

## 기타
- [공식 페이지 Cheatsheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/){:target="_blank"}를 보면 기타 여러가기 커맨드를 확인가능하다. 

# Kubernetes 오브젝트 
## Pod 
- 1개 또는 복수의 콘테이너를 묶어서 Pod라는 단위로 관리한다. 
- 주로 메인 컨테이너와 서포트 컨테이너를 하나의 Pod로 묶는 경우가 많다. (사이드카 패턴 혹은 어댑터 패턴)
- 예를들어, 어플리케이션 컨테이너와 메모리 캐시 혹은 모니터링용 컨테이너를 하나의 Pod으로 구동하는 경우가 있다. 혹은 웹 서버용 컨테이너와 프록시 서버용 컨테이너를 묶어서 하나의 pod로 관리한다.
- Node 보다 작은 단위이다. (참고로 하나의 pod가 복수의 Node에 포함되는 경우는 없다.) 
- Kubernetes 에서 디플로이의 최소 단위이다. 
- Pod 내의 컨테이너는 반드시 동일한 하드웨어에서 동작하낟. 
- Pod 내에서 네트워크나 스토리지 등 공유자원을 가진다. 
- 따라서, 동일 포트는 쓸 수 없다.
- localhost 로 컨테이너간에 통신이 가능하다. 

## Service
- Kubernetes 에서 서비스란 네트워크를 정의하는 녀석이다. 
- 복수의 Pod을 묶어서 서비스로 관리한다. 
- Pod마다 IP주소가 할당되므로 여러개의 Pod을 하나의 도메인명으로 묶어줄 필요가 생긴다. 
- 그를 위해서 Service가 등장. 

한편, Ingress 라는 Pod로의 통신을 제어하는 기능이 있다. 
Ingress 는 kubernetes 를 동작하는 환경에 따라 동작이 다르다. 예를들어 GCP에서는 HTTP 로드 밸런서가 사용된다. 

## Node
- 실제로 콘테이너가 동작하는 서버 
- 내부에 Pod 나 Service를 가지고 있다. 

## Cluster
- 복수의 노드를 묶어서 클러스터로 관리한다.  

## ConfigMap / Secret
- 컨테이너에게 OS환경변수를 주입하거나 설정등을 전달하기 위한 오브젝트
- 예를들어, 개발환경용 ConfigMap이나 운영환경용 ConfigMap이 있을 수 있다. 
- Secret은 기밀성이 높은 정보 관리용

## ReplicaSet (레플리카셋)
- 다수의 컨테이너를 어떻게, 몇 개나 구동할 것인지를 설정할 수 있다. 
- 레플리카셋에 설정된 컨테이너 개수는 항상 떠 있는 상태일 것을 kubernetes 가 담보해준다. 
- 예를 들어, 어떤 컨테이너가 어떤 이유로 다운되었을 경우, 새로운 컨테이너를 구동해준다. 
- 실제 업무에서 레플리카셋을 쓸 경우는 거의 없다. Deployment를 사용하게 된다. 레플리카셋은 갱신시에 적혀진 컨테이너가 전부 사라지므로 다운타임이 발생하게 되기 때문이다. 

## Deloyment
- ReplicaSet과 설정 항목이 비슷하다. 
- 레플리카셋과 비교해서 strategy (갱신전략, 예를들면 하나씩 갱신해가는 롤링 업데이트 등), revisionHistory, paused, progressDeadlineSeconds 등을 추가로 설정가능하다. 
- Deployment가 내부적으로는 복수의 레플리카셋을 사용하는 형태가 된다. 

## DaemonSet
- 로그 수집 프로그램등 어떤 서버상에 반드시 하나의 Pod는 실행시키고 싶은 경우에 사용
- 직접 쓰는 경우는 별로 없을지도 모른다. OSS 플러그인에서는 사용하는 경우가 있다. 

# Kubernetes 오브젝트 생성
##  필수 필드 
yaml 파일에 내용을 기술할 때 다음 네 개가 필수 필드다. 
1. apiVersion: 어떤 버전의 Kubernetes API를 쓸 것인지. ex) v1
2. kind: 어떤 종류의 오브젝트를 작성할 것인가 ex) Pod / Deployment...
3. metadata: 오브젝트를 식별하기 위한 정보. ex) name, UID, namespace...
4. spec: 이상적인 상태. containers 등을 기술 

# 트러블 슈팅
## kubectl 커맨드 실행시 Unable to connect to the server: Service Unavailable 가 표시되는 경우 
PC를 재구동하고 Docker Desktop을 시작하고 나서 kubectl을 사용했더니 Unable to connect to the server: Service Unavailable 이 출력되는 경우다. 
- 아래 커맨드로 상세 디버그 로그를 출력가능하다. 어디가 문제인지 알 수 있다. 
- 숫자는 0부터 9까지 설정가능하다. 9면 가장 상세하게 출력된다. 
- 내 경우에는 프록시 서버가 존재하는 것이 원인이었다. 
```sh
kubectl get nodes --v=9
```
해결책
- 환경변수 NO_PROXY 를 설정한다. 
- NO_PROXY 에 kubernetes.docker.internal 를 추가한다. 
- 이렇게 하면 kubectl이 kubernetes.docker.internal 에 연결할 때 프록시 서버를 통하지 않게 된다. 
- 참고: https://stackoverflow.com/questions/41482485/kubectl-behind-a-proxy



# 중요개념
## 네임스페이스
- kubernetes 내에서는 오브젝트 사이에 동일한 이름을 쓸 수 없다. (이름이 충돌되면 안된다.)
- 이름 충돌을 해결하기 위해서 네임스페이스가 있다. 

# 참고링크 
- 쿠버네티스란 (일본어): https://kubernetes.io/ja/docs/concepts/overview/what-is-kubernetes/ 
- 컴포넌트에 대해서: https://kubernetes.io/ko/docs/concepts/overview/components/