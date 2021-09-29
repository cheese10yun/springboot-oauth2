# 프로젝트 소개

Spring Boot 2.1 기반으로 Spring Security OAuth2를 살펴보는 프로젝트입니다. Authorization Code Grant Type, Implicit Grant, Resource Owner Password Credentials Grant, Client Credentials Grant Type OAuth2 인증 방식에 대한 간단한 셈플 코드부터 OAuth2 TokenStore 저장을 mysql, redis 등 저장하는 예제들을 다룰 예정입니다. 계속 학습하면서 정리할 예정이라 심화 과정도 다룰 수 있게 될 거 같아 깃허브 Start, Watching 버튼을 누르시면 구독 신청받으실 수 있습니다. 저의 경험이 여러분에게 조금이라도 도움이 되기를 기원합니다.

## 구성
* Spring Boot 2.1.0
* Spring Security OAuth2
* Lombok
* Java8
* MySQL
* Docker

## 목차

* [step-01 OAuth2 인증 방식 Flow 및 Sample Code](https://github.com/cheese10yun/springboot-oauth2/blob/master/docs/OAuth2-Grant.md)
* [step-02 토큰과 클라이언트 정보 RDBMS 저장](https://github.com/cheese10yun/springboot-oauth2/blob/master/docs/OAuth2-RDBMSt.md)
* [step-03 Redis를 이용한 토큰 저장 작업중...]()

**step-XX Branch 정보를 의미합니다. 보고 싶은 목차의 Branch로 checkout을 해주세요**

## Project 실행


### Docker MySQL 설정
```
$ cd springboot-oauth2
$ docker-compose up -d
```

### 애플리케이션 구동
* 최초 구동, MySQL Schema, Data Set Up 진행시 `"spring.profiles.active=init`
* 일반 구동시 `"spring.profiles.active=local`