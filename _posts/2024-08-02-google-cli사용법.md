---
layout: post
title: "구글 Cloud SDK 사용법 정리"
categories: [클라우드, Google Cloud, GCP]
categories: [클라우드, Google Cloud, GCP]
toc: true
last_modified_at: 2024-08-02 15:00:00 +0900
---


# 개요
- 구글 Cloud SDK 사용법을 정리해둔다. 
- 구글 Cloud SDK 에는 CLI(glcoud커맨드)와 클라이언트 라이브러리(SDK)가 포함된다. 
- 참고로 gcloud 는 파이썬으로 작성되었다 한다. 
- 참고로 GCP(Google Cloud Platform)은 옛날 이름이고 2022년부터는 Google Cloud가 정식 명칭이라고 한다. 

# 환경
Windows 10 

# 인스톨
[여기](https://cloud.google.com/sdk/docs/install-sdk?hl=ko)를 보고 Windows 인스톨러를 다운로드받아 설치한다. 


설치가 완료되면 바탕화면에 `Google Cloud SDK Shell`가 있는 것을 볼 수 있다. 경로는 유저폴더의 `\AppData\Local\Google\Cloud SDK` 다. 

# gcloud CLI 초기화

커맨드 라인에서 다음 명령어를 실행하면 웹 브라우저의 GCP화면으로 이동한다. 여기서 로그인하고 gclound CLI가 GCP 리소스에 접근할 수 있도록 허용한다. 기본적으로 화면에서 안내하는대로 따라가면 된다. 

```sh
gcloud init
```

# gcloud에 서비스 어카운트 설정하기 
어떤 권한을 부여받은 서비스 어카운트가 있고, 그 서비스 어카운트를 사용해서 작업을 하고 싶다면 [여기](https://cloud.google.com/sdk/gcloud/reference/auth/activate-service-account)를 참고한다. 

다음 커맨드를 사용해서 설정한다. 

```sh
gcloud auth activate-service-account SERVICE_ACCOUNT@DOMAIN.COM --key-file=/path/key.json --project=PROJECT_ID
```

# 각종 커맨드
## DNS 관련

관리중인 Zone정보를 본다. 

```sh
gcloud dns managed-zones list
```

## 프로젝트 관련
생성된 프로젝트 목록을 확인한다. 

```sh
gcloud projects list
```

# 파이썬에서 SDK를 이용하기 
- [여기](https://cloud.google.com/python/docs/supported-python-versions)에 따르면 현재는 모든 버전의 파이썬을 지원한다고 한다. 

## 라이브러리 인스톨
[여기](https://pypi.org/project/google-cloud/)에 의하면 2018년 6월 이후로 구글 클라우드 클라이언트에서는 boto3와 같은 all-in-one 라이브러리는 제공하지 않는다고 한다. 각 어플리케이션에서 필요한 서비스에 맞춰서 라이브러리를 설치해야 한다. 

다음 사이트에서 보면 수많은 구글 클라우드 라이브러리가 있는 것을 알 수 있다. 

https://pypi.org/search/?q=google-cloud&o=


예를들어 구글 클라우드 스토리지 같은 경우에는 커맨드라인에서 다음 커맨드로 설치한다. 

※ 윈도우즈에서는 커맨드라인을 관리자 권한으로 실행해야 한다. 

```sh
pip install --upgrade google-cloud-storage
```


```sh

```

## 인증설정
다음 커맨드로 ACD(Application Default Credentials)라는 것을 설정한다. 구글 웹 페이지로 이동되어 권한을 허용할 것인지를 확인한다. 허용해준다. 

```sh
gcloud auth application-default login
```

다음 코드에서 bucket_name을 적절히 변경한 뒤 실행시켜본다. 그러면 버킷이 생성된다. 콘솔에서 확인해보면 새로 생성된 버킷이 보인다. 

```py
# Imports the Google Cloud client library
from google.cloud import storage

# Instantiates a client
storage_client = storage.Client()

# The name for the new bucket
bucket_name = "my-new-bucket"

# Creates the new bucket
bucket = storage_client.create_bucket(bucket_name)

print(f"Bucket {bucket.name} created.")
```

## SDK 참고 정보
- `google-api` 와 `google-cloud-api`는 다르다. 
- 전자는 drive, calendar, maps 등의 서비스를 API를 경유로 핸들링할 수 있는 것이고, 후자는 bigquery, datastore, DNS 등 GCP의 서비스를 API 경유해서 핸들링할 수 있는 것이다. 

## 서비스 어카운트를 사용해서 DNS서비스 API 사용해보기 
대문자로된 CREDENTIAL_PATH와 PROJECT_NAME을 적절히 변경해서 사용한다. 

```py
from pprint import pprint

from googleapiclient import discovery
from oauth2client.client import GoogleCredentials
from google.cloud.dns.client import Client
import os

os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'CREDENTIAL_PATH'
# client = Client()
credentials = GoogleCredentials.get_application_default()


service = discovery.build('dns', 'v1', credentials=credentials)

project = 'PROJECT_NAME'

request = service.managedZones().list(project=project)
while request is not None:
    response = request.execute()

    for managed_zone in response['managedZones']:
        # TODO: Change code below to process each `managed_zone` resource:
        pprint(managed_zone)

    request = service.managedZones().list_next(previous_request=request, previous_response=response)
```

# 참고 
- 클라이언트 라이브러리 시작하기: https://cloud.google.com/storage/docs/reference/libraries#client-libraries-install-python
- Python Client for Cloud DNS API: https://cloud.google.com/python/docs/reference/dns/latest
- https://cloud.google.com/dns/docs/reference/rest/v1/managedZones/list