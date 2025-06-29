---
layout: post
title: "AWS Secrets Manager로 시크릿 주기적으로 교체하기"
categories: [AWS, AWS Secrets Manager]
tags: [AWS, AWS Secrets Manager, 시크릿 로테이션, rotation]
toc: true
last_modified_at: 2025-05-01 09:33:00 +0900
---

# 개요 
어플리케이션에서 시크릿(억세스 토큰을 포함한 각종 크레덴셜)을 환경변수나 파일등으로 고정해놓고 사용하는 경우가 많은데, 이런 경우 시크릿이 노출되면 어플리케이션이 매우 위험해진다. 주기적으로 시크릿을 갱신하는 체계를 갖춰놓으면 안심할 수 있다. 클라우드 서비스인 AWS Secrets Manager를 사용해서 시크릿을 주기적으로 교체하는 방법을 조사한다. 

참고로 어플리케이션에서 주기적으로, 그리고 자동으로 시크릿을 갱신하는 것은 OWASP SAMM2.0의 Secret Management의 레벨3 활동에도 정의되어 있다. 


# 유즈케이스
가장 대표적인 케이스는 AWS 의 서비스에 접근할 때 필요한 IAM 크레덴셜을 주기적으로 갱신해서 사용하는 것이 있을 수 있겠다. 

예를 들어 어떤 어플리케이션이 특정 S3버킷에 접근해서 데이터를 읽거나, 혹은 데이터를 S3에 업로드하기 위해서 IAM 크레덴셜을 사용하는 경우가 있다. 이 때 사용되는 IAM 크레덴셜을 주기적으로 변경하는 케이스를 상상할 수 있다. 


# 새로운 시크릿의 생성을 AWS에서 담당하지 않는 경우는?
IAM 크레덴셜과 같은 것은 AWS에서 관리하므로 AWS측에서 새로운 시크릿의 생성을 할 수 있을 것이다. 이 것을 [Managed rotation(관리된 순환)](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_managed.html)이라고 부른다. Amazon Aurora, Amazon ECS, Amazon RDS, Amazon Redshift등의 서비스가 Managed rotation을 제공한다. 그런데 그렇지 않는 경우는 어떨까? 예를들어 Github의 접근토큰을 새로 생성하려면 Github측에 요청해야 할 것이다. 이런 경우는 Lambda함수를 사용하면 된다. 이 것을 [Rotation by Lambda function](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_lambda.html)이라고 부른다. 


# 고정된 크레덴셜 실습
일단 바로 사용해보자. Secrets Manager에 시크릿을 등록하고 나면 각종 개발 언어로 시크릿을 가져오는 코드를 제공해준다. 파이썬의 경우는 다음처럼 생겼다. 

```py
# Use this code snippet in your app.
# If you need more information about configurations
# or implementing the sample code, visit the AWS docs:
# https://aws.amazon.com/developer/language/python/

import boto3
from botocore.exceptions import ClientError


def get_secret():

    secret_name = "SECRET_NAME"
    region_name = "ap-northeast-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    secret = get_secret_value_response['SecretString']

    # Your code goes here.

```

# 참고
- Rotate AWS Secrets Manager secrets: https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html
- Secrets Manager를 사용하여 주기적으로 Access Key 교체
출처: https://junhyeong-jang.tistory.com/19 [AWS 초보SA 성장일기:티스토리]: https://junhyeong-jang.tistory.com/19
- AWS Secrets Manager를 사용하여 IAM 액세스 키를 주기적으로 자동 교체하는 방안: https://repost.aws/ja/articles/ARlcBggX4aSf2j83UR1bvrrw/aws-secrets-manager%EB%A5%BC-%EC%82%AC%EC%9A%A9%ED%95%98%EC%97%AC-iam-%EC%95%A1%EC%84%B8%EC%8A%A4-%ED%82%A4%EB%A5%BC-%EC%A3%BC%EA%B8%B0%EC%A0%81%EC%9C%BC%EB%A1%9C-%EC%9E%90%EB%8F%99-%EA%B5%90%EC%B2%B4%ED%95%98%EB%8A%94-%EB%B0%A9%EC%95%88?sc_ichannel=ha&sc_ilang=ko&sc_isite=repost&sc_iplace=hp&sc_icontent=ARlcBggX4aSf2j83UR1bvrrw&sc_ipos=6
- AWS Secrets Manager - Rotate secrets up to every four hours: https://www.youtube.com/watch?v=D2aRrxUiaqQ