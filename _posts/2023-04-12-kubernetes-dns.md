---
layout: post
title: "쿠버네티스 Pod에 도메인 설정하기"
categories: [쿠버네티스]
tags: [쿠버네티스,도메인설정, kube-DNS]
toc: true
---

# 개요
- 쿠버네티스는 서비스와 파드를 위해서 DNS 레코드를 생성한다. 사용자는 IP 주소 대신에 일관된 DNS 네임을 통해서 서비스에 접속할 수 있다.
- 여기에서는 유저가 직접 도메인을 설정하는 방법을 알아본다. 

# 파드에 도메인 설정하기 
파드의 spec에 hostname과 subdomain을 설정할 수 있다. 예를들면 다음과 같다. 

```yaml 
apiVersion: v1
kind: Pod
metadata:
  name: pod-redis
spec:
  hostname: redis
  subdomain: mysub
  containers:
  - name: pod-redis
    image: redis
```

hostname은 `redis`로, subdomain은 `mysub`로 지정했다. 이렇게 설정하면 전체 도메인은 `redis.mysub.default.svc.cluster.local`이 된다. 대략 `(hostname).(subdomain).(namespace).(service).(cluster).(로컬DNS인지 리모트DNS인지?)` 과 같은 형식인 것 같다. 

위 내용을 `pod-redis.yaml`로 저장하고 다음 명령어로 파드를 생성한다. 

```sh
kubectl apply -f pod-redis.yaml
```

# DNS 값 테스트/디버깅 하기 
DNS값을 테스트/디버깅하기 위한 파드가 있으면 편하다. busybox를 추천한다. 

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: busybox
  namespace: default
spec:
  containers:
  - image: busybox
    command:
      - sleep
      - "3600"
    imagePullPolicy: IfNotPresent
    name: busybox
  restartPolicy: Always
```

위 내용을 `pod-busybox.yaml`로 저장하고 다음 명령어로 파드를 생성한다. 

```sh
kubectl apply -f pod-busybox.yaml
```

다음 명령어로 실행 결과를 확인한다. 

```sh
kubectl exec -ti busybox -- nslookup redis.mysub.default.svc.cluster.local
```

결과는 다음과 같았다. 설정이 잘 안된 것 같다. 원인이 뭘까?

```
Server:         10.96.0.10
Address:        10.96.0.10:53

** server can't find redis.mysub.default.svc.cluster.local: NXDOMAIN

** server can't find redis.mysub.default.svc.cluster.local: NXDOMAIN
```

# 커스텀 DNS 조회가 안되는 원인조사 
## 파드의 DNS 설정 확인 
일단 다음 명령으로 DNS 설정을 확인해본다. 

```sh
kubectl exec -ti busybox -- /bin/sh
cat /etc/resolv.conf
```

다음과 같이 되어 있다. 

```
nameserver 10.96.0.10
search default.svc.cluster.local svc.cluster.local cluster.local
```

다시 호스트 환경에서 확인해보면 `default.svc.cluster.local`까지는 조회가 잘되는데, 이 도메인의 서브도메인부터는 인식을 못하고 있다. 기본 DNS서버(CoreDNS)에 설정이 입력되지 않은 것 같다. 

```
kubectl exec -ti busybox -- nslookup default.svc.cluster.local
Server:         10.96.0.10
Address:        10.96.0.10:53
```

## DNS서버(CoreDNS)의 로그조사 

리눅스라면 다음 한줄의 명령으로 확인할 수 있지만, 윈도우즈라면 동작하지 않는다. 

```sh
kubectl logs --namespace=kube-system $(kubectl get pods --namespace=kube-system -l k8s-app=kube-dns -o name) -c coredns
```

다음과 같이 두 번으로 나눠서 실행해본다. 

```sh
# kube-dns서비스를 수행하는 파드명 확인
kubectl get pods --namespace=kube-system -l k8s-app=kube-dns -o name
# 위의 실행결과를 아래 명령어에 삽입
kubectl --namespace=kube-system logs {kube-dns서비스를 수행하는 파드명} -c coredns
```

또는 다음 명령으로도 확인가능하다. 

```sh
kubectl logs -l k8s-app=kube-dns -n kube-system
```

로그를 확인해보니 딱히 커스텀 설정한 DNS레코드가 보이지 않는다.  


https://stackoverflow.com/questions/54488280/how-do-i-get-individual-pod-hostnames-in-a-deployment-registered-and-looked-up-i
를 보면 Pod만으로 DNS 설정을 하는 것은 원래 안되는 것 같다. DNS설정(A 레코드 설정)은 Service를 통해서만 가능하다는 것 같다. 예외가 있다. 헤드리스 서비스(ClusterIP가 None인 서비스)를 사용하는 경우에는 설정할 수 있다고 한다. 

정리하면 Pod에 hostname과 subdomain을 설정하는 것만으로는 DNS서비스가 인식하지 않고 헤드리스 서비스를 함께 사용해야 한다. 

# 개선: 헤드리스 서비스에 도메인 설정하기 

`pod-redis.yaml`의 내용을 다음과 같이 수정했다. ClusterIP가 None인 헤드리스 서비스를 추가했다. name값이 mysub로 서브도메인명과 동일하다. (동일해야 하는게 필수사항인지는 모르겠다. 공식 문서에는 동일하게 되어있어서 동일하게 했다.) 그리고 Pod설정에서 labels가 추가되었다. Service는 labels의 name값으로 후보를 찾기 때문에 필요하다.

```yaml 
apiVersion: v1
kind: Service
metadata:
  name: mysub
spec:
  selector:
    name: pod-redis
  clusterIP: None
  ports:
  - name: foo # 매뉴얼에는 name이 옵션이라고 되어 있지만 이 값이 없으면 제대로 동작하지 않았다. 써두는게 좋겠다. 
    port: 1234
---
apiVersion: v1
kind: Pod
metadata:
  name: pod-redis
  labels:
    name: pod-redis
spec:
  hostname: redis
  subdomain: mysub
  containers:
  - name: pod-redis
    image: redis

```

리소스를 제거하고 다시 생성한다. 

```sh
kubectl delete -f pod-redis.yaml
kubectl apply -f pod-redis.yaml
```

`redis.mysub.default.svc.cluster.local` 도메인이 제대로 조회되는지 확인해본다. 

```sh
kubectl exec -ti busybox -- nslookup redis.mysub.default.svc.cluster.local
```

제대로 조회되는 것을 확인했다! 

```sh
kubectl exec -ti busybox -- nslookup redis.mysub.default.svc.cluster.local
Server:         10.96.0.10
Address:        10.96.0.10:53


Name:   redis.mysub.default.svc.cluster.local
Address: 10.1.0.141

```

# 참고 
- https://kubernetes.io/ko/docs/concepts/services-networking/dns-pod-service/
- https://arisu1000.tistory.com/27859
- https://stackoverflow.com/questions/58426493/deployment-in-version-v1-cannot-be-handled-as-a-deployment