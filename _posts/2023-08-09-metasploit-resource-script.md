---
layout: post
title: "Metasploit 취약점 체크 자동화하는 방법"
categories: [보안, 취약점스캐너]
tags: [취약점, 스캐너, metasploit]
toc: true
last_modified_at: 2023-08-10 10:02:00 +0900
---

# 개요
- Metasploit 의 기본CLI에서 제공하는 기능을 프로그래밍할 수 있는지(CLI커맨드 입력작업을 자동화할 수 있는지) 확인한다. 
- Metasploit을 사용한 체크를 자동화 (여러개의 타겟에 대해 일괄적으로 체크하는 작업)하기 위해서는 Resource Script가 필요하다는 것을 알게 되었다. 
- Resource Script를 사용하는 방법을 정리해둔다. 
- 스크립트 내에서 Metasploit 콘솔 커맨드를 조합해서 사용할 수도 있고, API 를 호출해서 사용할 수도 있다. 

# 리소스 스크립트(Resource Script)
- .rc 확장자를 가진 파일로 구성된다. 
- 설치 환경마다 다를 수도 있지만 내 경우는 `/opt/metasploit-framework/embedded/framework/scripts/resource` 경로에 설치되어 있다. 
- rc파일은 Run Command 의 약자로, 리눅스같은 환경에서 커맨드입력을 자동화하는 목적으로 사용되는 것 같다. 

# 간단한 리소스 스크립트 작성하고 실행하기 
- 간단하다. 그냥 Metasploit CLI에서 입력하는 커맨드를 그대로 나열하면 된다. 
- 예를들어 test.rc 파일을 다음과 같이 작성할 수 있다. 

```
use auxiliary/scanner/http/apache_optionsbleed
set RHOSTS xxxx.xxxxx.com
set RPORT 443
exploit
```

작성한 파일을 다음과 같이 `-r` 옵션과 함께 실행하면 CLI 커맨드가 자동으로 입력되면서 체크가 수행된다. 

```sh
msfconsole -r test.rc
```

# 리소스 스크립트 문법
Metasploit에 포함되어 있는 리소스 스크립트를 확인해보면 대략 어떻게 코드를 짜는지 알 수 있다. 

## 주석
주석은 `#`로 표현한다. `#`로 시작하는 라인은 주석으로 처리된다. 

## 루비 코드
`<ruby></ruby>` 태그 안에 루비 코드를 적으면 된다. 

### Metasploit CLI커맨드 실행하기 
rc 파일 내에서 라면 그냥 쓰면 되고, 루비코드 내에서라면 `run_single` 함수에 커맨드를 파라메터로 넘겨주면 된다. 예를들어 위에서 간단한 리소스 스크립트를 작성한 것을 ruby코드로 다음과 같이 쓸 수 있다. 하는 일은 동일하다. 

```ruby
<ruby>
run_single("use auxiliary/scanner/http/apache_optionsbleed")
run_single("set RHOSTS xxxx.xxxxx.com")
run_single("set RPORT 443")
run_single("exploit")
</ruby>
```

## 상태 출력하기 
`<ruby>` 태그 내에서 `print_status` 함수로 프로그램의 상태를 출력한다. 표준 ruby에는 없는 함수로 보인다. 예를들면 다음과 같다. 

```ruby
<ruby>
print_status("Starting Browser Autopwn with Firefox-only BrowserExploitServer-based exploits.")
print_status("Older Firefox exploits don't use BES, therefore will not be loaded.")
```


# 여러개의 대상으로 스캔하기 
- 그러면 한번에 여러 서버를 대상으로 스캔하려면 어떻게 해야 하는지 조사해본다. 
- 다음과 같은 패턴이 많이 쓰이는 것 같다. 
- Metasploit 프레임워크에 내장되어 있는 DB에 저장된 hosts를 대상으로 뭔가 작업을 하는 코드다.
- 일단 내장 DB에 데이터를 읽고 쓰는 방법을 알아야 겠다. 

```ruby
<ruby>
framework.db.hosts.each do |host|
	host.services.each do |serv|  # 서비스가 있다면 해당 서비스들에 대해서도 작업을 수행 
    ...
    end
end
</ruby>
```

## 내장된 DB에 hosts입력하기 
내장된 DB를 왜 사용하는걸까? (사용하면 얻을 수 있는 이점은 뭘까? )

https://www.offsec.com/metasploit-unleashed/database-introduction/ 에 의하면, 스캔을 수행하면서 수행한 작업이 기록된다는 것 같다. 확실히 이 작업을 자동으로 해준다면 꽤 시간을 절약할 수 있을 것 같다. 

그러면 내장된 DB에 hosts는 어떻게 입력하는걸까? 

### 일반적인 경우 
- 일반적인 경우는 Nmap스캔의 수행 결과가 바로 저장되는 것 같다. 
- 콘솔에서 `db_nmap`커맨드로 Nmap스캔을 수행할 수 있다. 
- nmap 스캔 결과 발견된 포트가 해당 서버의 서비스로 저장되는 것 같다. 

```
msf > db_nmap -A 172.16.194.134
```

### 수동으로 직접 입력하기 
`hosts -a` 커맨드로 추가할 수 있다. 도메인을 지정할 경우 도메인의 IP주소값(DNS의 A레코드 값)이 hosts에 저장된다. 참고로 존재하지 않는 도메인이라면 저장되지 않는다. 

```
msf > hosts -a "xxxx.com"
```

### 수동으로 대량을 입력하기 
rc 스크립트를 짜면 될 것 같다. 예들 들어 타겟 목록을 targets.txt 라는 파일에 저장해두었다고 하면 다음과 같이 짜면 되겠다. 이 파일이 add_target.rc라고 하면 `msfconsole -r add_target.rc` 커맨드로 스캔 대상을 일괄적으로 입력할 수 있다. 

```ruby
<ruby>
File.readlines('targets.txt').each do |line|
    run_single("hosts -a #{line}")
end
</ruby>
```

### hosts 초기화하기
참고로 hosts를 초기화하려면(등록된 host를 모두 삭제하려면) 어떻게 해야할까?

`-d` 옵션만 주면 모두 삭제된다. 

```
msf > hosts -d
```

## 스캔 수행하기 
DB에 데이터를 읽고 쓰는 방법을 대략 알아봤다. 그러면 DB에 저장된 host를 대상으로 스캔을 수행해본다. 

다음과 같이 하면 되겠다. 

```ruby
<ruby>
framework.db.hosts.each do |host|
	run_single("use auxiliary/scanner/http/apache_optionsbleed")
    run_single("set RHOSTS #{host}")
    run_single("set RPORT 443")
    run_single("exploit")
end
</ruby>
```

그런데 위를 실행하면 다음과 같은 에러가 발생한다. 

```
[-] Msf::OptionValidateError The following options failed to validate: RHOSTS
RHOSTS => #<Mdm::Host:0x00007f0d45c29580>
```

뭔가 이상해서 puts 함수로 직접 출력을 해봤다. 그랬더니 IP주소값을 예상한 부분이 다음과 같이 출력되는 것을 볼 수 있었다. 오브젝트가 출력된 것이다. 

```
#<Mdm::Host:0x00007fd818a023a8>
```

위 코드의 `#{host}`는 `#{host.address}`로 바꿔야 제대로 동작한다. 

```ruby
<ruby>
framework.db.hosts.each do |host|
	run_single("use auxiliary/scanner/http/apache_optionsbleed")
    run_single("set RHOSTS #{host.address}")
    run_single("set RPORT 443")
    run_single("exploit")
end
</ruby>
```

### 더 간단한 방법
좀 더 조사해보니 RHOSTS에는 여러 대상을 지정할 수 있다는 것 같다. 따라서 다음과 같이 하면 더 간단하겠다. 마지막에 exit도 써준다. 

```
use auxiliary/scanner/http/apache_optionsbleed
<ruby>
run_single("set RHOSTS #{framework.db.hosts.map(&:address).join(' ')}")
</ruby>
set RPORT 443
exploit
exit
```


# 결과를 판정하기 
여러번의 조사를 수행했을 때, 취약했다고 판정난 서버만을 알고 싶으면 어떻게 해야하는가? 스캔 수행이력이 DB에 저장된다고 하니 DB를 조사하는 방법을 알아내면 될 것 같다. 

## vulns 커맨드
- 이 커맨드를 사용하면 exploit이 성공해서 취약점을 찾아낸 결과를 보여준다고 한다. 
- 그런데 취약하다고 나왔는데도 커맨드 쳐보면 아무것도 표시되지 않는 경우가 있다. 

## loot커맨드
- loot는 전리품, 노획물이란 뜻이다. 
- exploit을 성공한 후에 어떤 정보인지 판정할 수는 없지만 뭔가 가치있어보이는 정보를 보여주는 것 같다. 

## 리눅스 리다이렉트를 사용
그냥 다음와 같이 실행하고 결과를 저장해두고 나중에 결과 txt파일을 확인하는게 속편해보인다. 이 방법을 써야겠다. 

```sh
msfconsole -r scan_hosts.rc > scan_result.txt & 
```

# 참고 
- https://docs.rapid7.com/metasploit/resource-scripts/
- https://tx-driver.hatenablog.com/entry/2018/12/31/100000
- https://www.offsec.com/metasploit-unleashed/using-databases/