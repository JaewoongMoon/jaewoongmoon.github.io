---
layout: post
title: "EKS 간단 사용법"
categories: [쿠버네티스, EKS]
tags: [쿠버네티스, EKS]
toc: true
---


# 개요 
- Fargate를 사용하는 EKS 사용법을 정리해둔다.
- [EKS 간단사용법]({% post_url 2023-04-14-eks-tutorial %}) 에서 컴퓨팅 엔진이 EC2가 아니라 Fargate를 사용하는 부분만 바뀐 것이다. 

# 방법
- eksctl을 이용해 클러스터를 만들 때 옵션으로 `--fargate`를 지정해주면 된다. 
- `--fargate`를 지정하면 노드그룹이 만들어지지 않는다고 한다. 
- 시간은 30분정도 걸린다. 

```sh
eksctl create cluster \
  --name eks-example \
  --fargate
```



# 참고
- https://dev.classmethod.jp/articles/eksctl-usage-for-eks-fargate/