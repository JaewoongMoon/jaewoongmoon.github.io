


# Timeless Timing Attack
- 네트워크에는 노이즈(jitter)가 존재하기 때문에 응답시간(요청을 보낸 후에 응답이 도착할 때까지의 시간)을 비교하는 것은 신뢰성이 떨어진다.
- 따라서 이 기법에서는 동시성(Concurrency)개념을 사용한다. 동시에 여러 요청을 보낸 후에 되돌아오는 응답의 순서에만 집중하자는 접근법이다. 
- 이는 네트워크 노이즈(jitter)에 영향을 받지 않기 떄문에 로컬 시스템에 대해 공격하는 것과 비슷한 정확도의 결과가 나오게 된다. 
- => HTTP/2에서 사용가능한 "Single Packet Attack" 으로 이어진다. 

# 참고
- https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work#front-end-impersonation
- https://www.usenix.org/conference/usenixsecurity20/presentation/van-goethem