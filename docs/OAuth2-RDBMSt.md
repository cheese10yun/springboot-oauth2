## 목차
- [목차](#%EB%AA%A9%EC%B0%A8)
- [데이터베이스 스키마 구성하기](#%EB%8D%B0%EC%9D%B4%ED%84%B0%EB%B2%A0%EC%9D%B4%EC%8A%A4-%EC%8A%A4%ED%82%A4%EB%A7%88-%EA%B5%AC%EC%84%B1%ED%95%98%EA%B8%B0)
    - [oauth_client_details table](#oauthclientdetails-table)
- [프로젝트 구동](#%ED%94%84%EB%A1%9C%EC%A0%9D%ED%8A%B8-%EA%B5%AC%EB%8F%99)
    - [OAuth2 테이블](#oauth2-%ED%85%8C%EC%9D%B4%EB%B8%94)
- [Code](#code)
    - [Resource Owner Password Credentials Grant](#resource-owner-password-credentials-grant)
        - [요청](#%EC%9A%94%EC%B2%AD)
        - [응답](#%EC%9D%91%EB%8B%B5)
    - [Authorization Code Grant Type](#authorization-code-grant-type)
        - [요청](#%EC%9A%94%EC%B2%AD-1)
        - [응답](#%EC%9D%91%EB%8B%B5-1)
    - [입력된 데이터](#%EC%9E%85%EB%A0%A5%EB%90%9C-%EB%8D%B0%EC%9D%B4%ED%84%B0)
- [참고](#%EC%B0%B8%EA%B3%A0)

## 데이터베이스 스키마 구성하기

가장 먼저 데이터베이스를 생성해야합니다.

```
mysql> create database oauth2;
```

```yml
spring:
  profiles: init
  jpa:
    database: mysql
    properties.hibernate.dialect: org.hibernate.dialect.MySQL5InnoDBDialect
    hibernate:
      ddl-auto: create
    show-sql: true
    properties:
      hibernate.format_sql: true
  datasource:
    url: jdbc:mysql://localhost:3306/oauth2?useSSL=false&serverTimezone=UTC
    username: <your-usesrname>
    password: <your-password>
    driver-class-name: com.mysql.cj.jdbc.Driver
    initialization-mode: always
    platform: oauth2
```

데이터 베이스 구성을 위한 profile을 구성합니다. 해당 profile은 OAuth2에 대한 스키마 생성 및 더미데이터를 insert 해줍니다. 

`datasource.platform` 속성 값에 `oauth2`가 입력되어 있습니다. 간단하게 설명드리면 `resources`에 위치한 `${platform}.sql`을 실행시킵니다.

프로젝트에 `resources` 디렉토리에는 `schema-oauth2.sql`, `data-oauth2.sql`가 존재하고 각각은 테이블 스미카, `oauth_client_details` 더미데이터 insert 입니다. 세부적인 sql 파일을 직접 확인하는것을 권장드립니다.

프로젝트의 profile은 init으로 구동시에 `schema-oauth2.sql` , `data-oauth2.sql`가 실행됩니다. 프로젝트 실행시에 딱 한번만 init으로 진행하시고 이후 부터는 local로 진행하시면 됩니다.


### oauth_client_details table
```sql
INSERT INTO `oauth_client_details`(
  `client_id`,
  `resource_ids`,
  `client_secret`,
  `scope`,
  `authorized_grant_types`,
  `web_server_redirect_uri`,
  `authorities`,
  `access_token_validity`,
  `refresh_token_validity`,
  `additional_information`,
  `autoapprove`
  )

  VALUES(
  'client',
  null,
  '{bcrypt}$2a$10$iP9ejueOGXO29.Yio7rqeuW9.yOC4YaV8fJp3eIWbP45eZSHFEwMG',
  'read_profile,read_posts',
  'authorization_code,implicit,password,client_credentials,refresh_token',
  'http://localhost:9000/callback',
  null,
  3000,
  6000,
  null ,
  'false'
  );
```
* client_id : 클라이언트를 구분하는 ID
* client_secret : 클라이언트의 비밀번호로 OAuth2 서버에 요청할때 인증을 하기위한 용도로 사용한다.
* authorized_grant_types: OAuth2 승인 방식의 종류 `...`, `...` 이런 형식으로`,`를 이용해서 구분한다.
* access_token_validity : Access Token의 유효시간
* refresh_token_validity : Refresh Token의 유효 시간
* scope: 클라이언트로 발급된 Access Token의 Scope, 리소스에 접근 가능한 권한 구분은 `,` 으로한다
* autoapprove: 권한코드 방식 같은 형태로 Access Token을 발급받을 때에는 사용자에게 scope 범위를 허가받는 화면이 나옵니다. 이 화면 자체가 나오지 않게 설정하는 값입니다. true하면 아래 화면이 나오지 않습니다.

![](/assets/oauth-prove.png)
  

## 프로젝트 구동
```yml
spring:
  profiles:
    active: init # 기본은 local로 되어있습니다.
```

프로젝트를 실행할때 `application.yml` 최상단에 있는 active를 local로 변경합니다. **스키마, 더미데이터 입력이 목적이기 때문에 프로젝트 최초 1회 구동시 init으로 진행하시고 이후는 local로 진행하면됩니다.**



### OAuth2 테이블 
![ouath2-schema](/assets/ouath2-schema.png)

프로젝트를 구동하면 테이블 생성 및 더미데이터를 확인 할 수 있습니다.


## Code
이전에 코드에 몇가지 빈들을 등록하게 되면 간단하게 RDBMS에 토큰 정보를 저장할 수 있습니다.

```java
@Configuration
@EnableAuthorizationServer
@AllArgsConstructor
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private final DataSource dataSource; // (1)


    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .jdbc(dataSource) // (5)
        ;
//기존 코드
//                .inMemory()
//                .withClient("client")
//                .secret("{bcrypt}$2a$10$iP9ejueOGXO29.Yio7rqeuW9.yOC4YaV8fJp3eIWbP45eZSHFEwMG")  // password
//                .redirectUris("http://localhost:9000/callback")
//                .authorizedGrantTypes("authorization_code", "implicit", "password", "client_credentials", "refresh_token")
//                .accessTokenValiditySeconds(120)
//                .refreshTokenValiditySeconds(240)
//                .scopes("read_profile"); 
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        //@formatter:off
        endpoints //(4)
                .approvalStore(approvalStore())
                .tokenStore(tokenStore())
                .authenticationManager(authenticationManager)
        ;
        //@formatter:on
    }

    @Bean
    public TokenStore tokenStore() { //(2)
        return new JdbcTokenStore(dataSource);
    }

    @Bean
    public ApprovalStore approvalStore() { //(3)
        return new JdbcApprovalStore(dataSource);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```
* (1) 토큰에 대한 영속화를 진행하기 위해서 `Datasoruce` 의존성을 주입받습니다.
* (2) 주입 받은 `Datasoruce` 의존성을 기반으로 `JdbcTokenStore`을 생성합니다.
* (3) 2번과 마찬가지로 `Datasoruce`을 주입시켜 `JdbcApprovalStore`을 생성합니다.
* (4) 2,3 번에서 생성한 객체을 `AuthorizationServerEndpointsConfigurer` 객체에 넣어줍니다.
* (5) clinet `inMemory()` 방식에서 `jdbc()` 방식으로 변경합니다. 의존성은 dataSource 주입해줍니다.

TokenStore 인터페이스는 Access Token, Refresh Token과 관련된 인증 데이터를 저장, 검색, 제거, 읽기에 대한 정의입니다.
ApprovalStore 인터페이스는 리소스의 소유자의 승인을 추가, 검색, 취소 하기위한 메서드들이 정의되있습니다.

**이렇듯 스프링에서는 인터페이스를 재공함으로써 확장포인트를 열어두어 확장에는 열려있는 모듈을 지향하고 있습니다.**

대표적으로 Resource Owner Password Credentials Grant, Authorization Code Grant Type 인증을 살펴보겠습니다.

### Resource Owner Password Credentials Grant

#### 요청
```bash
curl -X POST \
  http://localhost:8080/oauth/token \
  -H 'Authorization: Basic Y2xpZW50OnBhc3N3b3Jk' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=user&password=pass&grant_type=password&scope=read_profile'
```

#### 응답
```json
{
  "access_token": "a7cce128-bd4a-4986-a56b-de75f5246364",
  "token_type": "bearer",
  "refresh_token": "a7c43419-4875-47f5-9d79-829301ed0030",
  "expires_in": 871,
  "scope": "read_profile"
}
```

### Authorization Code Grant Type

#### 요청
[http://localhost:8080/oauth/authorize?client_id=client&redirect_uri=http://localhost:9000/callback&response_type=code&scope=read_profile](http://localhost:8080/oauth/authorize?client_id=client&redirect_uri=http://localhost:9000/callback&response_type=code&scope=read_profile) 해당 페이지로 이동

![oauth2-login](/assets/oauth2-login.png)
로그인 정보를 입력합니다.

```
username: user
password: pass
```

![oauth-code](/assets/oauth-prove.png)

![oauth-code](/assets/oauth-code.png)
권한 승인이 완료하면 권한 코드가 전송됩니다. [Authorization Code Grant Type 방식](#authorization-code-grant-type-%EB%B0%A9%EC%8B%9D) 에서 말한 `권한 부여 코드`를 응답받은 것입니다. 

넘겨받은 승인 코드로 Authorization Code Grant 인증을 진행합니다.

```bash
curl -X POST \
  http://localhost:8080/oauth/token \
  -H 'Authorization: Basic Y2xpZW50OnBhc3N3b3Jk' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'code=rNHo29&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcallback&scope=read_profile'
```
만약 IntelliJ를 사용하신다면 `api.http`를 이용해서 더 쉽게 호출 해볼 수 있습니다.
![ouath2-http](/assets/ouath2-http.png)

#### 응답
```json
{
  "access_token": "883c329b-8f05-457c-907c-ce8637a7aa80",
  "token_type": "bearer",
  "refresh_token": "a7c43419-4875-47f5-9d79-829301ed0030",
  "expires_in": 2942,
  "scope": "read_profile"
}
```

### 입력된 데이터
![oauth2-table-access-token](/assets/oauth2-table-access-token.png)
![oauth2-table-refresh-token](/assets/oauth2-table-refresh-token.png)

위에서 발급 받은 Access Token, Refresh Token을 확인 할 수 있습니다.


## 참고
* [Spring Boot로 만드는 OAuth2 시스템 8 OAuth2 서버를 커스터마이징 해보자(클라이언트 관리 편)](https://brunch.co.kr/@sbcoba/8)
* [OAuth 2.0 쿡북](http://www.kyobobook.co.kr/product/detailViewKor.laf?ejkGb=KOR&mallGb=KOR&barcode=9791161752211&orderClick=LAG&Kc=)