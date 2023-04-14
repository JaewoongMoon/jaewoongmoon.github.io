---
layout: post
title: "쿠버네티스 프라이빗 Dockerhub 리포지토리 사용하기"
categories: [쿠버네티스]
tags: [쿠버네티스, 프라이빗 Dockerhub 리포지토리]
toc: true
---

# 개요
- 쿠버네티스에서 프라이빗 도커 리포지토리의 이미지를 가져오는 방법을 조사한다. 
- [여기](https://kubernetes.io/ko/docs/concepts/containers/images/#%ED%94%84%EB%9D%BC%EC%9D%B4%EB%B9%97-%EB%A0%88%EC%A7%80%EC%8A%A4%ED%8A%B8%EB%A6%AC-%EC%82%AC%EC%9A%A9)에 의하면 프라이빗 레지스트리를 사용하는 몇 가지 방법이 설명되어 있다. 도커 허브의 프라이빗 리포지토리를 사용하는데는 주로 파드에 `ImagePullSecrets`을 명시하는 방법이 사용되는 것 같다. 

# 시크릿 생성하기 
먼저 프라이빗 도커에 접근하기 위한 시크릿(자격증명)을 생성한다. 

## 도커 구성으로 시크릿 생성하기 
다음 명령으로 시크릿을 생성한다. name 부분을 적절히 변경한다. 참고로 name에 언더바(_)는 쓸 수 없다. 

- 도커허브라면 `DOCKER_REGISTRY_SERVER`값을 `docker.io`로 하면 된다. 
- 만약 `DOCKER_PASSWORD`에 특수문자등이 포함될 경우 쌍따옴표로 전체를 감싸서 지정하자. 

```sh
kubectl create secret docker-registry <name> --docker-server=DOCKER_REGISTRY_SERVER --docker-username=DOCKER_USER --docker-password=DOCKER_PASSWORD --docker-email=DOCKER_EMAIL
```

## 기존의 자격 증명을 기반으로 시크릿 생성하기
- [여기](https://kubernetes.io/ko/docs/tasks/configure-pod-container/pull-image-private-registry/#registry-secret-existing-credentials)에 의하면 도커허브에 이미 계정을 가지고 있다면 이 것을 사용할 수 있다는 것 같다. 
- 쿠버네티스 클러스터는 프라이빗 이미지를 받아올 때, 컨테이너 레지스트리에 인증하기 위하여 `kubernetes.io/dockerconfigjson` 타입의 시크릿을 사용한다. 만약 이미 `docker login` 을 수행하였다면, 이 때 생성된 자격 증명을 쿠버네티스 클러스터로 복사할 수 있다. 

아래 커맨드의 `<path/to/.docker/config.json>`부분을 `.docker/config.json`가 존재하는 패스로 변경한다. Windows환경이라면 절대 경로가 필요한 것 같다. `C:\Users\{USERNAME}\.docker\config.json`과 같은 형식이다. 

```sh
kubectl create secret generic regcred \
    --from-file=.dockerconfigjson=<path/to/.docker/config.json> \
    --type=kubernetes.io/dockerconfigjson
```

정상적으로 실행되었다면 다음과 같은 메세지가 출력된다. 

```sh
secret/regcred created
```

## 생성된 시크릿 확인 
다음 명령으로 확인할 수 있다. 

```sh 
kubectl get secrets
```

다음과 같은 결과나 출력된다. 

```sh 
NAME      TYPE                             DATA   AGE
regcred   kubernetes.io/dockerconfigjson   1      13m
```

# 시크릿을 사용하여 도커 이미지에 접근하기 
## 파드에 imagePullSecrets 추가하여 접근하기 
- imagePullSecrets 섹션을 파드의 정의에 추가함으로써 해당 시크릿을 참조하는 파드를 생성할 수 있다.
- 예를들면 다음과 같은 식이다. 

```yaml
cat <<EOF > pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: foo
  namespace: awesomeapps
spec:
  containers:
    - name: foo
      image: janedoe/awesomeapp:v1
  imagePullSecrets:
    - name: regcred
EOF
```

## 서비스 어카운트에 imagePullSecrets 추가하여 접근하기 
위의 설정은 각 파드에 추가할 필요가 있다. 설정할 파드가 여러개라면 귀찮아 진다.    
이럴때는 서비스 어카운트 리소스에 imagePullSecrets을 셋팅하여 자동화할 수 있다. 다음 명령을 사용한다. 

```sh
kubectl patch serviceaccount default -p '{"imagePullSecrets": [{"name": "regcred"}]}'
```

내 경우엔 다음과 같은 에러가 발생했다. 

```
Error from server (BadRequest): invalid character 'i' looking for beginning of object key string
```

이럴 때는 다음 명령을 사용해서 수동으로 서비스 어카운트를 편집할 수 있다.

```sh
kubectl edit serviceaccount/default
```

실행하면 메모장으로 파일이 열린다. 다음과 같이 수정하면 된다. 

```yaml 
apiVersion: v1
kind: ServiceAccount
metadata:
  creationTimestamp: 2021-07-07T22:02:39Z
  name: default
  namespace: default
  uid: 052fb0f4-3d50-11e5-b066-42010af0d7b6
imagePullSecrets:
  - name: regcred
```
