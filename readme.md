Facebook Login Practice
===

Facebook 로그인 문서의 [로그인 플로 직접 빌드](https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#confirm) 파트를 Flask를 사용한 웹 애플리케이션으로 구현해보았습니다.

## Setup
1. Facebook Client 정보 등이 담긴 `config/secret.py`를 만들어야합니다. `config/secret.py.example`를 참조하세요.
2. DB 테이블 생성
```python
>>> from application import db
>>> db.create_all()
```
