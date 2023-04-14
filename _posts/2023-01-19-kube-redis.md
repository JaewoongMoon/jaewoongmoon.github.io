---
layout: post
title: "Redis를 이용한 쿠버네티스 병렬처리"
categories: [쿠버네티스]
tags: [쿠버네티스, Redis, 병렬처리]
toc: true
---

# 개요 
- https://kubernetes.io/ko/docs/tasks/job/fine-parallel-processing-work-queue/ 를 참고해서 실습해본다. 

# 실습
## 대기열 채우기
먼저 작업을 대기열에 채워야 한다. 대기열을 관리하는 시스템은 RabbitMQ(래빗엠큐)나 Redis(레디스)가 있다. 이 샘플에서는 레디스 서버를 사용한다. 

### 레디스 서버 구동
다음 명령으로 temp라는 이름으로 redis서버용 Pod를 생성하고 셸로 로그인한다. 

```sh
kubectl run -i --tty temp --image redis --command "/bin/sh"
```

다음 명령으로 redis서버를 구동한다. 구동했으면 셸을 종료해도 된다. 

```sh
redis-server
```

### 데이터(Job) 준비 
다음 커맨드로 redis용 컨테이너에 접속한다. 

```sh
kubectl exec --stdin --tty temp -- /bin/bash
```

컨테이너 접속하는데 성공했으면 다음 커맨드로 redis 클라이언트에 접속한다. 

```sh
redis-cli
```

만약 다음과 같은 에러가 나왔다면 redis서버가 구동되지 않은 상태일 가능성이 높다.   
(참고: https://stackoverflow.com/questions/42857551/could-not-connect-to-redis-at-127-0-0-16379-connection-refused-with-homebrew)

```
Could not connect to Redis at 127.0.0.1:6379: Connection refused
```

다음 커맨드로 잡 리스트를 생성한다. `job2`라는 키(대기열목록)에 잡이 저장된다.    
알파벳순서대로 10개의 잡을 생성했다. 

```sh
rpush job2 "apple"
rpush job2 "banana"
rpush job2 "cherry"
rpush job2 "date"
rpush job2 "fig"
rpush job2 "grape"
rpush job2 "lemon"
rpush job2 "melon"
rpush job2 "orange"
rpush job2 "pickle"
```

다음 커맨드로 job2의 내용을 조회할 수 있다. 

```sh
lrange job2 0 -1
```

다음과 같은 내용이 조회된다. 

```
127.0.0.1:6379> lrange job2 0 -1
1) "apple"
2) "banana"
3) "cherry"
4) "date"
5) "fig"
6) "grape"
7) "lemon"
8) "melon"
9) "orange"
```

redis 커맨드의 의미는 다음과 같다. 
- `rpush (key) (element)`: 리스트의 오른쪽에 데이터를 저장한다. 
- `lrange (key) (start) (stio)`: 키에 저장된 데이터를 조회한다. 0 -1 을 지정하면 처음부터 끝까지 조회한다는 의미이다. 


## 워커 이미지 생성
워커 이미지 생성을 위해서 worker.py, rediswq.py, Dockerfile 이 필요하다. 

### 파이썬 워커 프로그램(worker.py)

```py
#!/usr/bin/env python

import time
import rediswq

# host="redis" 
# Uncomment next two lines if you do not have Kube-DNS working.
import os
host = os.getenv("REDIS_SERVICE_HOST") 

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

### redis헬퍼 (rediswq.py) 
redis 와의 통신을 도와주는 헬퍼 라이브러리이다. 

```py
#!/usr/bin/env python

# Based on http://peter-hoffmann.com/2012/python-simple-queue-redis-queue.html 
# and the suggestion in the redis documentation for RPOPLPUSH, at 
# http://redis.io/commands/rpoplpush, which suggests how to implement a work-queue.

 
import redis
import uuid
import hashlib

class RedisWQ(object):
    """Simple Finite Work Queue with Redis Backend

    This work queue is finite: as long as no more work is added
    after workers start, the workers can detect when the queue
    is completely empty.

    The items in the work queue are assumed to have unique values.

    This object is not intended to be used by multiple threads
    concurrently.
    """
    def __init__(self, name, **redis_kwargs):
       """The default connection parameters are: host='localhost', port=6379, db=0

       The work queue is identified by "name".  The library may create other
       keys with "name" as a prefix. 
       """
       self._db = redis.StrictRedis(**redis_kwargs)
       # The session ID will uniquely identify this "worker".
       self._session = str(uuid.uuid4())
       # Work queue is implemented as two queues: main, and processing.
       # Work is initially in main, and moved to processing when a client picks it up.
       self._main_q_key = name
       self._processing_q_key = name + ":processing"
       self._lease_key_prefix = name + ":leased_by_session:"

    def sessionID(self):
        """Return the ID for this session."""
        return self._session

    def _main_qsize(self):
        """Return the size of the main queue."""
        return self._db.llen(self._main_q_key)

    def _processing_qsize(self):
        """Return the size of the main queue."""
        return self._db.llen(self._processing_q_key)

    def empty(self):
        """Return True if the queue is empty, including work being done, False otherwise.

        False does not necessarily mean that there is work available to work on right now,
        """
        return self._main_qsize() == 0 and self._processing_qsize() == 0

# TODO: implement this
#    def check_expired_leases(self):
#        """Return to the work queueReturn True if the queue is empty, False otherwise."""
#        # Processing list should not be _too_ long since it is approximately as long
#        # as the number of active and recently active workers.
#        processing = self._db.lrange(self._processing_q_key, 0, -1)
#        for item in processing:
#          # If the lease key is not present for an item (it expired or was 
#          # never created because the client crashed before creating it)
#          # then move the item back to the main queue so others can work on it.
#          if not self._lease_exists(item):
#            TODO: transactionally move the key from processing queue to
#            to main queue, while detecting if a new lease is created
#            or if either queue is modified.

    def _itemkey(self, item):
        """Returns a string that uniquely identifies an item (bytes)."""
        return hashlib.sha224(item).hexdigest()

    def _lease_exists(self, item):
        """True if a lease on 'item' exists."""
        return self._db.exists(self._lease_key_prefix + self._itemkey(item))

    def lease(self, lease_secs=60, block=True, timeout=None):
        """Begin working on an item the work queue. 

        Lease the item for lease_secs.  After that time, other
        workers may consider this client to have crashed or stalled
        and pick up the item instead.

        If optional args block is true and timeout is None (the default), block
        if necessary until an item is available."""
        if block:
            item = self._db.brpoplpush(self._main_q_key, self._processing_q_key, timeout=timeout)
        else:
            item = self._db.rpoplpush(self._main_q_key, self._processing_q_key)
        if item:
            # Record that we (this session id) are working on a key.  Expire that
            # note after the lease timeout.
            # Note: if we crash at this line of the program, then GC will see no lease
            # for this item a later return it to the main queue.
            itemkey = self._itemkey(item)
            self._db.setex(self._lease_key_prefix + itemkey, lease_secs, self._session)
        return item

    def complete(self, value):
        """Complete working on the item with 'value'.

        If the lease expired, the item may not have completed, and some
        other worker may have picked it up.  There is no indication
        of what happened.
        """
        self._db.lrem(self._processing_q_key, 0, value)
        # If we crash here, then the GC code will try to move the value, but it will
        # not be here, which is fine.  So this does not need to be a transaction.
        itemkey = self._itemkey(value)
        self._db.delete(self._lease_key_prefix + itemkey)

# TODO: add functions to clean up all keys associated with "name" when
# processing is complete.

# TODO: add a function to add an item to the queue.  Atomically
# check if the queue is empty and if so fail to add the item
# since other workers might think work is done and be in the process
# of exiting.

# TODO(etune): move to my own github for hosting, e.g. github.com/erictune/rediswq-py and
# make it so it can be pip installed by anyone (see
# http://stackoverflow.com/questions/8247605/configuring-so-that-pip-install-can-work-from-github)

# TODO(etune): finish code to GC expired leases, and call periodically
#  e.g. each time lease times out.

```

### Dockerfile
도커 이미지를 빌드하기 위한 파일이다. pip으로 redis 라이브러리를 설치하는 부분도 포함되어 있다. 

```
FROM python
RUN pip install redis
COPY ./worker.py /worker.py
COPY ./rediswq.py /rediswq.py

CMD  python worker.py
```

### 이미지 빌드
다음 명령으로 이미지를 빌드한다. 조금 시간이 걸린다. 

```sh
docker build -t job-wq-2 .
```

빌드가 완료된 후 `docker images` 명령으로 확인해보면 다음과 같이 이미지가 생성된 것을 확인할 수 있다. 

```
REPOSITORY       TAG         IMAGE ID       CREATED          SIZE
job-wq-2         latest      75b1e7fb5fb8   34 seconds ago   934MB
```

## 워커 이미지 푸시
도커 허브에 푸시한다. 아래의 명령어를 이용해 앱 이미지를 사용자의 username으로 태깅하고 도커허브에 푸시한다. <username>을 사용자의 허브 username으로 대체한다.

```sh
docker tag job-wq-2 <username>/job-wq-2
docker push <username>/job-wq-2
```

만약 다음과 같은 메세지나 나타난다면 도커허브에 로그인되어 있지 않은 것이다. 

```
denied: requested access to the resource is denied
```

다음 명령어로 로그인한 후 다시 푸시를 시도한다. (퍼블릭 리포지토리로 푸시된다.)

```
docker login 
```

## 잡 정의(job.yaml)
쿠버네티스 잡을 정의하는 파일이다. 2라인으로 병렬처리를 수행한다. 다음과 같이 환경변수 `REDIS_SERVICE_HOST` 를 ConfigMap을 사용해 삽입했다. 

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
data:
  REDIS_SERVICE_HOST: 10.1.0.85

---
apiVersion: v1
kind: Pod
metadata:
  name: pod-wq-2
spec:
  containers:
  - name: job-wq-2-pod-test
    image: jwmoon/job-wq-2
    envFrom:
        - configMapRef:
            name: test-config
```


## 잡 실행 

다음 명령어로 잡을 실행한다. 

```sh
kubectl apply -f ./job.yaml
```

조금 기다린 뒤 다음 명령어로 상태를 확인한다. 

```sh
kubectl describe jobs/job-wq-2
```

다음과 같은 상태를 확인할 수 있다. 두 개의 파드가 생성된 것을 확인할 수 있다. 

```sh
Name:             job-wq-2
Namespace:        default
Selector:         controller-uid=9de54c27-2612-4b35-9a67-222ab92c1acc
Labels:           controller-uid=9de54c27-2612-4b35-9a67-222ab92c1acc
                  job-name=job-wq-2
Annotations:      batch.kubernetes.io/job-tracking:
Parallelism:      2
Completions:      <unset>
Completion Mode:  NonIndexed
Start Time:       Tue, 11 Apr 2023 15:05:34 +0900
Pods Statuses:    2 Active (0 Ready) / 0 Succeeded / 0 Failed
Pod Template:
  Labels:  controller-uid=9de54c27-2612-4b35-9a67-222ab92c1acc
           job-name=job-wq-2
  Containers:
   c:
    Image:        job-wq-2
    Port:         <none>
    Host Port:    <none>
    Environment:  <none>
    Mounts:       <none>
  Volumes:        <none>
Events:
  Type    Reason            Age   From            Message
  ----    ------            ----  ----            -------
  Normal  SuccessfulCreate  12s   job-controller  Created pod: job-wq-2-mcbpr
  Normal  SuccessfulCreate  12s   job-controller  Created pod: job-wq-2-vz7cz
```

Pod이름을 지정해서 로그를 확인할 수 있다. 

```sh
kubectl logs pods/job-wq-2-mcbpr
```

잡이 실행된 결과가 출력된다. 다음은 각 두개의 Pod의 실행 결과이다. Pod마다 5개씩 Job이 실행된 것을 확인할 수 있다. 또한, 잡이 들어갈 때와는 반대의 순서로(가장 마지막에 넣은 Job이 먼저 실행되었다, FIFO방식) 실행된 것도 확인할 수 있었다. 

```sh
Worker with sessionID: 628e5a32-6c8c-4c0e-8aab-98ec4bee8aac
Initial queue state: empty=False
Working on pickle
Working on melon
Working on grape
Working on date
Working on banana
Waiting for work
Waiting for work
Queue empty, exiting
```

```sh
Worker with sessionID: 23485166-4d38-488c-9c29-44300250aab0
Initial queue state: empty=False
Working on orange
Working on lemon
Working on fig
Working on cherry
Working on apple
Queue empty, exiting
```
