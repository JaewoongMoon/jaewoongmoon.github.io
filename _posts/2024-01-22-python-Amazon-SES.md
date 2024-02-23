---
layout: post
title: "파이썬으로 Amazon SES를 통해 메일보내기"
categories: [파이썬, 메일전송, Amazon SES]
tags: [파이썬, 메일전송, Amazon SES]
toc: true
last_modified_at: 2024-01-23 21:15:00 +0900
---

# 개요
Amazon Simple Email Service (SES)를 사용해보고 **메일 송신을 위한 설정 과정**을 정리해둔다. 

# 순서
1. SMTP settings 메뉴에서 SMTP 크레덴셜을 만들고 다운로드해둔다. CSV파일이다. 안에 SMTP 유저명과 패스워드가 적혀있다. 

2. 정당한 송신자인지를 AWS에게 보여줄 필요가 있다. 이를 위해 송신측 도메인을 인증하거나 (조금 어렵다) 이메일 주소의 소유자임을 인증한다(쉽다). 이메일 주소 인증은 이메일에 링크가 도착하면 그 링크에 접근하는 것으로 소유자임을 인증한다. 

3. 1번에서 받은 크레덴셜을 가지고 로컬환경에서 메일을 보내본다. 파이썬 코드도 정리해둔다. 
- 각 항목을 적절히 변경해서 사용한다. 
- 587번 포트를 사용한다. 25번 포트를 사용할 수 있다면 25번을 사용해도 무방하다. 

```py
# -*- coding: utf-8 -*-
import smtplib
from email.message import EmailMessage


def send_mail():
    msg = EmailMessage()
    msg['From'] = "FROM-EMAIL-ADDRESS"
    msg['To'] = "TO-EMAIL-ADDRESS"
    msg['Cc'] = "CC-EMAIL-ADDRESS"
    msg['Subject'] = "Amazon SES Test"
    content = f"Test Mail\r\n\r\n"
    msg.set_content(content)
    
    smtp_user_name = "SMTP-USER-NAME"
    smtp_user_pw = "SMTP-USER-PASSWORD"

    server = smtplib.SMTP('AWS-SMTP-SERVER-DOMAIN', 587)
    server.starttls()
    server.login(smtp_user_name, smtp_user_pw)
    server.send_message(msg)
    server.quit()


if __name__ == '__main__':
    send_mail()
```

4. 문제가 없었다면 EC2서버환경에서 메일을 보내본다. 이 때 EC2 Securtiy Group에서 아웃바운드 통신 제한을 하고 있다면 587포트를 허가해준다. 
- SMTP서버 도메인의 IP가 계속 변하기 때문에 특정 IP만 허용하는 것은 어렵다. 모든 IP 주소에 대해 587포트를 허용할 수 밖에 없다. 또는 Dedicated IP 주소를 설정하는 방법도 고려할 수 있겠다. 


# 참고 
- SES는 Region별로 설정한다. 
- SDK(boto3)를 사용해서 전송할 수도 있다고 한다. 