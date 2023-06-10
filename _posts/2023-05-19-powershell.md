---
layout: post
title: "셸스크립트를 Powershell스크립트로 변환하기 팁 모음 "
categories: [Powershell]
tags: [Powershell]
toc: true
---

# 개요
- 셸스크립트에서 자주 보이는 특정 패턴을 파워셸에서 동일하게 하려고 하면 어떻게 작성해야 할까?

# Powershell에서 셸스크립트처럼 환경변수 사용하기
- 셸스크립트에서 커맨드의 실행결과를 변수에 담아서 사용하는 패턴을 종종 볼 수 있다. 
- 파워셸에서 같은 것을 하려고 하면 어떻게 작성해야 할까?
- 예를 들면, 다음과 같은 경우이다. 

```sh
export POD_NAME=$(kubectl get pods --namespace default -l "app=build-code" -o jsonpath="{.items[0].metadata.name}")
# 변수에 저장한 후에는 $로 불러서 쓸 수 있다. 
kubectl port-forward $POD_NAME 
```

파워셸로는 그냥 변수$를 붙이면 된다. (https://stackoverflow.com/questions/68018145/export-set-environment-variables-in-windows-through-a-shell-script)

```powershell
$POD_NAME=kubectl get pods --namespace default -l "app=build-code" -o jsonpath="{.items[0].metadata.name}"
```


# `> /dev/null 2>&1` 변환하기 
- 셸스크립트에서 `특정 커맨드 > /dev/null 2>&1` 와 같은 패턴을 종종볼 수 있다. 
- 파워셸에서도 동일한 일을 하기 위해 일단 이 것의 의미를 다시 정리해둔다. 
- https://stackoverflow.com/questions/10508843/what-is-dev-null-21를 참고했다. 
- `>`는 "truncate and write"를 의미한다. 
- `/dev/null`은 버리라는 의미다. (블랙홀이라고도 불린다.)
- `2>&1`은 스탠다드 에러(`2`)를 스탠다드 아웃풋(`1`)으로 리다이렉트하라는 의미다. (두 아웃풋이 합쳐진다)
- 정리하면 `특정 커맨드 > /dev/null 2>&1`의 의미는 커맨드의 실행결과를 `/dev/null`로 보낸다. 이 때 스탠다드 에러도 같이 보낸다(`2>&1`)라는 의미이다. 
- 결국, 커맨드를 실행하는 동안 이것저것 출력하지 말고 조용히 하라는 의미이다. 

- 파워셸에서는 이렇게 쓴다고 한다. (https://superuser.com/questions/777198/equivalent-of-foo-dev-null-in-windows-shell)
- 내PC에서는 제대로 동작하지 않는다. 

```powershell
> NUL 2>&1
```

# 커맨드 백그라운드 실행(&)
- 셸스크립트에서 커맨드의 가장 마지막 &를 붙이면 백그라운드로 실행된다. 
- 파워셸에서는 다음과 같이 한다고 한다. 
- https://stackoverflow.com/questions/185575/powershell-equivalent-of-bash-ampersand-for-forking-running-background-proce

```powershell
Start-Process -NoNewWindow 커맨드
```

```powershell
Start-Process -NoNewWindow ping google.com
```

- 그러나 일부 커맨드(파라메터가 많은 커맨드?)는 동작하지 않는 것 같다. 
- 예를들면 다음과 같은 에러메세지나 나온다. 

```
Start-Process : 引数 'xxxx' を受け入れる位置指定パラメーターが見つかりません。
```