---
layout: post
title: "쿠버네티스 Redis 를 연동한 병렬처리"
categories: [쿠버네티스]
tags: [쿠버네티스, Redis, 병렬처리]
toc: true
---

# 개요 
- https://kubernetes.io/ko/docs/tasks/job/fine-parallel-processing-work-queue/ 를 참고해서 실습해본다. 

# 실습
## 대기열 채우기
### 레디스 서버 구동
```sh
kubectl run -i --tty temp --image redis --command "/bin/sh" 
redis-server
```

### 데이터(Job) 준비 
```sh
kubectl exec --stdin --tty temp -- /bin/bash
redis-cli
rpush job2 "apple"
rpush job2 "banana"
rpush job2 "cherry"
rpush job2 "date"
rpush job2 "fig"
rpush job2 "grape"
rpush job2 "lemon"
rpush job2 "melon"
rpush job2 "orange"
lrange job2 0 -1
```
## 워커 이미지 생성
### 파이썬 워커 프로그램

```py
#!/usr/bin/env python

import time
import rediswq

host="127.0.0.1"
# Uncomment next two lines if you do not have Kube-DNS working.
# import os
# host = os.getenv("REDIS_SERVICE_HOST")

q = rediswq.RedisWQ(name="job2", host=host)
print("Worker with sessionID: " +  q.sessionID())
print("Initial queue state: empty=" + str(q.empty()))
while not q.empty():
  item = q.lease(lease_secs=10, block=True, timeout=2)
  if item is not None:
    itemstr = item.decode("utf-8")
    print("Working on " + itemstr)
    time.sleep(10) # Put your actual work here instead of sleep.
    q.complete(item)
  else:
    print("Waiting for work")
print("Queue empty, exiting")
```

### 이미지 빌드
```sh
docker build -t job-wq-2 .
```

## 워커 이미지 푸시


## 잡 정의

## 잡 실행 


# 참고 
- https://stackoverflow.com/questions/42857551/could-not-connect-to-redis-at-127-0-0-16379-connection-refused-with-homebrew
