---
layout: post
title: "쿠버네티스 Indexed Job 사용법"
categories: [쿠버네티스]
tags: [쿠버네티스, 쿠버네티스 Job]
toc: true
---

# 개요
- kubernetes에서 병렬처리를 하기 위한 방법중에 작업큐를 사용하지 않는 방법을 검토한다. 
- 이유는 작업큐를 준비하는데도 시간이 들고, 각 Pod와 작업큐간에 통신비용도 꽤나 발생하는 것처럼 보이기 때문이다. 
- 작업리스트는 각 Pod에 미리 저장해두고, 각 Pod가 알아서 다른 Pod와 겹치지 않게(이거 중요하다!) 작업을 진행해주면 매우 편리할 것이다. 
- 이를 위해서 Indexed Job이라는 것을 사용할 수 있을 것 같다. 

# 포인트
1. 매니페스트를 적을 때 `completionMode: Indexed`를 지정해야 한다. 다음과 같다. 

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: 'sample-job'
spec:
  completions: 3
  parallelism: 3
  completionMode: Indexed
  template:
    spec:
      restartPolicy: Never
      containers:
      - command:
        - 'bash'
        - '-c'
        - 'echo "My partition: ${JOB_COMPLETION_INDEX}"'
        image: 'docker.io/library/bash'
        name: 'sample-load'
```

2. `JOB_COMPLETION_INDEX`라는 환경변수 값이 각 Pod에 자동으로 부여되는 것 같다. 
이 값을 사용해서 각 Pod에서 Job목록중에서 자신이 처리해야할 Job이 몇 번째 인덱스의 것인지 판단하는데 사용할 수 있을 것 같다. 

# 실습
(TODO) 한번 튜토리얼대로 진행해본다. 

# ref
- Indexed Job을 소개하는 블로그글: https://kubernetes.io/blog/2021/04/19/introducing-indexed-jobs/
- Indexed Job튜토리얼: https://kubernetes.io/docs/tasks/job/indexed-parallel-processing-static/