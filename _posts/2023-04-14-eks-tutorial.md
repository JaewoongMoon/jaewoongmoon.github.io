---
layout: post
title: "EKS 간단 사용법"
categories: [쿠버네티스, EKS]
tags: [쿠버네티스, EKS]
toc: true
---


# 개요 
AWS의 EKS를 사용하는 방법을 정리해둔다.

# 전제조건
- 최신버전의 AWS CLI가 설치되어 있어야 한다. 
- 최신버전의 eksctl가 설치되어 있어야 한다. 
- 최신버전의 kubectl이 설치되어 있어야 한다. 

## eksctl 설치
- https://docs.aws.amazon.com/ko_kr/eks/latest/userguide/eksctl.html

Windows에서는 다음 명령을 관리자권한으로 실행한 커맨드라인 툴에서 실행한다. 

```
choco install -y eksctl 
```

# 작업 흐름
## EKS작업용 IAM 유저를 생성하고 권한 부여
1. AWS의 IAM 웹 콘솔에서 EKS작업용 유저를 생성한다. 
2. 유저에 EKS관련 권한 부여(Policy)
상당히 많은 권한이 필요하다. 일일히 확인하기가 힘드므로 이 부분은 관리자 권한이 속편할 듯 싶다. 
(EKS관련 권한, EC2 도메인 조회관련권한, CloudFormation 관련 권한, IAM 폴리시 수정권한도 필요한 듯 하다. )

## EKS 작업용 유저를 Local 환경에서 사용할 수 있도록 설정
AWS Configure로 EKS 용 유저를 사용할 수 있는 Profile생성하고 억세스 키, 시크릿을 설정해둔다. 

## eksctl을 사용하여 클러스터 생성 

```sh
eksctl create cluster --name test-cluster --region us-east-1 --profile eks-user
```

이 클러스터는 기본적으로 두 개의 노드(m5.large타입 인스턴스)를 포함한다. 물론 좀 더 세밀하게 노드개수나 인스턴스 타입도 지정할 수 있다. 이걸 하려면 매니페스트파일(yaml파일)을 만들어서 지정하면 된다. 

### 팁: 클러스터 생성시의 VPC제한에 대해서 
- 클러스터 생성시에 VPC도 소비한다. 
- AWS 기본 설정상 각 리젼당 생성할 수 있는 VPC수는 5개로 제한되어 있다. 
- 따라서 이미 5개를 쓰고 있다면 새롭게 클러스터 생성이 안된다. 
- 이럴 때는 ServiceQuota 서비스에 들어가서 해당 리전을 선택한 후 (웹 콘솔 오른족 상단에서 리젼변경), `VPCs per Region` 에 대한 quota 상항 변경을 신청하면 된다. (30분에서 한시간정도 시간이 걸린다. AWS내에서 사람이 직접확인하는걸까?)


## 새로 만든 클러스터를 사용할 수 있도록 kubeconfig 업데이트
다음 명령을 사용해서 새로 만든 클러스터를 제어할 수 있는 상태로 만든다. 

```sh
aws eks update-kubeconfig --name test-cluster --profile eks-user
``` 

다음 명령으로 kubeconfig 결과를 확인한다. 그러면 test-cluster 클러스터가 추가된 것을 확인할 수 있다. 또한, current-context가 test-cluster로 되어 있는 것을 확인할 수 있다. 

```sh
cat ~/.kube/config 
```

## 클러스터 상태 확인 
다음 명령으로 쿠버네티스 노드 상태를 확인한다. 두 개의 노드가 생성되어 있는 것을 확인할 수 있다. 

```
kubectl get node
```

만약 다음과 같은 에러가 발생한다면 AWS CLI나 kubectl버전이 낣은 것이어서 그렇다. 양쪽 모두 최신 버전을 설치한다. 그리고 다시 한번더 `aws eks update-kubeconfig` 커맨드를 실행해서 설정을 업데이트 한다. 

```
error: exec plugin: invalid apiVersion "client.authentication.k8s.io/v1alpha1"
```

## 새로 만든 클러스터에 쿠버네티스 리소스 디플로이 작업
kubectl 을 사용해서 원하는대로 쿠버네티스 리소스를 만든다. 

## 작업이 끝난 후 삭제 작업
쿠버네티스 리소스와 클러스터를 각각 삭제한다. 

### 쿠버네티스 리소스 삭제
먼저 사용이 끝난 쿠버네티스 리소스를 kubectl 을 사용해서 삭제한다. 

### 클러스터 삭제
- 아래 명령으로 클러스터를 삭제한다. 
- 클러스터를 삭제하지 않으면 계속 사용비용이 발생한다. 한달에 대략 73달러 정도이다. 
- 이 과정도 꽤 시간이 걸린다. 
- 클러스터 생성시에 자동으로 같이 생성되었던 AWS 리소스(EKS클러스터, EC2인스턴스, VPC, CloudFormation 등)도 같이 삭제된다. 

```sh
eksctl delete cluster --name test-cluster --region us-east-1
```

### IAM 유저 삭제
유저를 재사용할 것이 아니라면 유저도 삭제해둔다. 

1. ~/.aws/credentials 와 ~/.aws/config 에서 해당 유저를 삭제한다. 
2. AWS 웹 콘솔에서 IAM서비스에서 해당 유저를 삭제한다. 


### kubeconfig에서 현재 클러스터(current-context)를 로컬환경(DockerDesktop)으로 변경
- kubeconfig의 current-context가 삭제된 클러스터를 가리키고 있으므로 DockerDesktop을 향하도록 바꿔둔다. 
- `~/.kube/config`를 직접 수정한다. current-context를 docker-desktop으로 바꿔두면 된다. 
