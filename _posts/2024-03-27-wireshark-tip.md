---
layout: post
title: "Wireshark 팁"
categories: [네트워크, 패킷캡처, Wireshark]
tags: [네트워크, 네트워크, 패킷캡처]
toc: true
---

# 개요 
네트워크 패킷 캡쳐툴인 와이어 샤크(Wireshark) 팁을 정리해둔다. 

# 필터링
## ip 주소

```sh
ip.src==127.0.0.1 or ip.dst==127.0.0.1
```

## Port 번호

```sh
tcp.port eq 25 or icmp
```


# 참고 
- https://wiki.wireshark.org/DisplayFilters