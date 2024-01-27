# mz-office

# APP List
## 1. app
테스트를 위한 App, 샘플 코드, 테스트 코드, index page, API DOCS 문서 등 사용

## 2. OAuth
OAuth를 이용한 소셜 로그인 기능 사용

[SangjunCha님의 GitHub 및 블로그 참고하여 작성](https://github.com/SangjunCha-dev/django-oauth)
 - 카카오 (완료)
 - 애플
 - 네이버
 - 구글

### 2-1. Client 테스트
- /oauth/kakao/login/
- oauth 로그인이 정상적으로 완료되면 `{"social_id": ..., "access_token": ..., "refresh_token": ...}` 값이 반환
- `/swagger/` 접속하여 우측상단에 `Authorize`버튼 클릭한다.
- 방금전에 발급받은 `access_token`을 입력하고 `Authorize`버튼 클릭한다.
- users의 `GET /users/info/` 요청을 전송하면 사용자의 정보가 출력된다.

## 3. user
회원 관리 App, 로그인, 로그아웃, 회원 정보 조회 등

## 4. question
메인 앱, mz-office에서 사용하는 질문 관련 앱 모음
