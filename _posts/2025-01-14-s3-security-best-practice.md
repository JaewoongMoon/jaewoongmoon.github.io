---
layout: post
title: "S3 보안 베스트 프랙티스 조사"
categories: [클라우드보안,AWS,S3]
tags: [클라우드보안,AWS,S3]
toc: true
last_modified_at: 2025-01-14 09:33:00 +0900
---

# 개요
S3를 안전한 상태로 운용하기 위한 베스트 프랙티스를 조사해둔다. 

특히, S3의 설정으로 인증되지 않은 접근자체는 차단하더라도, 에러 응답페이지에서 다양한 정보가 노출되는 경우가 있는데, 어떤 메타정보가 노출되면 어떤 면에서 위험한 것인지, 그리고 어떻게 대응해야 하는지를 정리한다. 

# 메모
- AWS의 서명 메커니즘도 공부해두면 좋겠다. 
- 

# 참고
- Kali를 사용한 S3 테스트 방법: https://www.securityblue.team/blog/posts/understanding-public-s3-buckets-data-leaks
- 캐노니컬 요청 생성 AWS문서: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html#create-canonical-request
- AWS의 API를 이해하자!(일본어): https://aws.amazon.com/jp/builders-flash/202210/way-to-operate-api-2/