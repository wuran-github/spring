# Spring Cloud OAuth2
  
- OAuth2是一个标准的授权协议。
- OAuth2允许不同的客户端通过认证和授权的形式来访问被其保护起来的资源。在认证和授权的过程中，主要包含以下3种角色。
    - 服务提供方Authorization Server
    - 资源持有者 Resource Server
    - 客户端 Client

- 认证流程如下：
    1. 用户(资源持有者)打开客户端，客户端询问用户授权。
    2. 用户同意授权。
    3. 客户端向授权服务器申请授权。
    4. 授权服务器向客户端进行认证，包括用户信息的认证，认证成功后授权给予令牌。
    5. 客户端获取令牌后，携带令牌向资源服务器(服务提供方)请求资源。
    6. 资源服务器确认令牌正确无误，向客户端释放资源。

## Spring OAuth2
- Spring中的Spring Oauth2(下面简称SO)实现了Oauth2。SO分为两部分，分别是OAuth2 Provider(下面简称OP)和OAuth2 Client(下面简称OC)。

### OAuth2 Provider
- OAuth2 Provider负责公开被OAth2保护起来的资源。OP需要配置代表用户的OAuth2客户端信息，被用户允许的客户端就可以访问被OAuth2保护的资源。

- OP通过管理和验证OAuth2令牌来控制客户端是否有权限访问被其保护的资源。

- OP还必须为用户提供认证API接口。根据接口，用户提供账号和密码等信息，来确认客户端是否可以被OP授权。
    - 这样的好处是第三方客户端不需要获取用户的账号和密码，通过授权的方式就可以访问被OAuth2保护起来的资源。

- OP的角色被分为
    - Authorization Service(授权服务，下称AS)
    - Resource Service(资源服务,下称RS)
- 通常不在同一个服务，可能一个AS对应多个RS。SO须配合SS一起使用。所有的请求由Spring MVC控制器处理，经过一系列的SS过滤器。

- 在SS过滤器链中有2个节点，这2个节点是向AS获取验证和授权的。
    - 授权节点:默认为/oauth/authorize
    - 获取Token节点：默认为/oauth/token

#### Authorization Server 配置
- 在配置AS时，需要考虑客户端从用户获取访问令牌的授权类型(例如授权代码、用户凭据、刷新令牌)。AS需要配置客户端的详细信息和令牌的实现。

- 在任何实现了AuthorizationServerConfigurer接口的类上加@EnableAuthorizationServer注解，开启AS的功能，注入Spring。并需要实现以下三个配置：
    - ClientDetailsServiceConfigurer:配置客户端信息
    - AuthorizationServerEndpointsConfigurer:配置授权Token的节点和Token服务。
    - AuthorizationServerSecurityConfigurer:配置Token节点的安全策略。

- 下面具体描述这三个配置。

1. ClientDetailsServiceConfigurer
    - 客户端的配置信息既可以放在内存中，也可以放在数据库中。需要配置如下信息：
    - clientId: 客户端Id，在AS中唯一。
    - secret: 客户端的密码
    - scope: 客户端的域
    - authorizedGrantTypes: 认证类型
    - authorities: 权限信息。
- 客户端的信息可以存储在数据库。SO设计好了数据库的表，且不可变。

2. AuthorizationServerEndpointsConfigurer

- 在默认情况下， AuthorizationServerEndpointsConfigurer配置开启了所有的验证类型，除了密码类型的验证。密码验证只有配置了authenticationManager的配置才会开启。
- AuthorizationServerEndpointsConfigurer配置由以下五项组成：
    - authenticationManager: 只有配置了该项，密码认证才会开启。
    - userDetailsService:配置获取用户认证信息的接口。
    - authorizationCodeServices: 配置验证码服务。
    - implicitGrantService： 配置管理implict验证的状态。
    - tokenGranter: 配置Token Granter。

- 另外，需要设置Token的管理策略。目前支持以下三种：
    - InMemoryTokenStore: Token存储在内存中。
    - jdbcTokenStore: 存储在数据库中。需要引入spring-jdbc的依赖包，并配置数据源，以及初始化SO的数据库脚本。
    - JwtTokenSotre:采用JWT形式，这种形式不需要存储，因为JWT本身包含了用户验证的所有信息。需要引入spring-jwt的依赖。

3. AuthorizationServerSecurityConfigurer

- 如果资源服务和授权您服务实在同一个服务中，用默认的配置即可，不需要做其他任何的配置。如果不是，则需要一些额外的配置。
- 如果采用RemoteTokenServices(远程Token校验)，资源服务器的每次请求所携带Token都需要从授权服务做校验。这时需要配置 /oauth/check_token 校验节点的校验策略。

#### Resource Server 的配置
- RS提供了受OAuth2保护的资源，这些资源为API接口、HTML页面，JS文件等。
- SO提供了实现此保护功能的的SS认证过滤器。
- 在加了@Configuration注解的配置类上加@EnableResourceServer注解，开启RS的功能，并使用ResourceServerConfigurer继续配置，需要配置以下的内容：
    - tokenServices: 定义Token Service。
        - 例如用ResourceServerToeknservices类，配置Token是如何编码和解码的。
        - 如果RS和AS在同一个工程内则不需要配置，否则需要配置。
        - 可以用RemoteTokenServices类，即RS采用远程授权服务器进行Token解码，这时也不需要配置此选项。
    - resourceId: 资源Id.


### OAuth2 Client
- OC用于访问被OA保护起来的资源，客户端需要提供用于存储用户的授权码和访问令牌的机制，需要配置如下2个选项：
    - Protected Resource Configuration(受保护资源配置)
    - Client Configuration(客户端配置)

#### Protected Resource Configuration
- 使用OAuth2ProtectedResourceDetails类型的Bean来定义受保护的资源，受保护的资源具有以下属性：
    - Id: 资源的Id，在SO中没用到，不需要配置，默认即可。
    - clientId: OC的Id，和之前OP的配置一一对应。
    - clientSecret: 客户端密码，和OP的配置对应。
    - accessTokenUri: 获取Token的API节点。
    - scope: 客户端的域。
    - clientAuthenticationScheme: 两种客户端验证类型，分别为Http Basic和Form。默认前者。
    - userAuthorizationUri: 如果用户需要授权访问资源，则用户被重定向到的认证Uri。


#### Client Configuration
- 对于OC的配置，可以使用@EnableOAuth2Client注解来简化配置。另外还需要配置以下两项：
    - 创建一个过滤器Bean(Bean的Id为oauth2ClientContextFilter)，用来存储当前请求和上下文的请求。在请求期间，如果用户需要进行身份验证，则用户会被重定向到OAuth2的认证URI。
    - 在Request域内创建AccessTokenRequest类型的Bean。

---
## 案例分析
- 首先看架构，分别由3个工程，服务注册中心eureka-server，授权中心Uaa工程auth-service和资源中心service-hi。

1. 浏览器向auth-service服务器提供客户端信息、用户名和密码，请求获取Token。
2. auth-service确认无误后，根据信息生成Token返回给浏览器。
3. 浏览器在以后的每次请求都携带Token给资源服务service-hi。
4. 资源服务获取到请求携带的Token后，通过远程调度将Token给授权服务auth-service确认。
5. auth-service确认Token正确无误后，将该Token对应的用户权限信息返回给资源服务。
6. 如果该Token对应的用户具有访问该API接口的权限，就正常返回请求，否则返回权限不足的错误。

### Eureka Server
- 和前面描述的一样


### Uaa授权服务
#### pom依赖
-  创建一个auth-service作为Uaa服务，同时是一个eureka-client，其POM依赖如下：
    - spring-cloud-starter-oauth2是对spring-cloud-starter-security spring-security-oauth2 spring-security-jwt这3个起步依赖的整合。
```
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-oauth2</artifactId>
        </dependency>
  <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
        </dependency>
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
```

#### application.yml
- 内容如下：
```
server:
  port: 5000
  servlet:
    context-path: /uaa #所有路由加上该前缀

#security:
#  oauth2:
#    resource:
#      #filter-order: 过时了

eureka:
  client:
    service-url:
        defaultZone:
          http://localhost:8761/eureka/
spring:
  application:
    name: auth-service
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: "jdbc:mysql://localhost:3306/spring_cloud_auth?
    useSSL=false&useUnicode=true&
    characterEncoding=UTF-8&
    allowPublicKeyRetrieval=true&serverTimezone=GMT%2B8"
    username: root
    password: root
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
```
- 配置了服务名，端口号，Mysql相关内容，以及服务注册中心的地址。

#### 配置Spring Security
- 由于auth-service需要对外暴露检查Token的API接口，所以auth-service也是一个资源服务，需要在工程中引入Spring Security，并作相关的配置。
- 配置代码如下：创建一个配置类
```
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest()
                .authenticated()
                .and()
                .csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(new BCryptPasswordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
}
```

- WebSecurityConfig类通过@EnableWebSecurity注解开启Web保护功能，通过@EnableGlobalMethodSecurity注解开启在方法上的保护功能。
- WebSecurityConfig类继承了WebSecurityConfigurerAdapter类，并复写了以下3个方法做配置：
    - configure(HttpSecurity): HttpSecurity中配置了所有的请求的需要做安全验证

    - configure(AuthenticationManagerBuilder): AuthenticationManagerBuilder中配置了验证的用户信息源和密码加密的策略，并且向Ioc容器中注入了AuthenticationManager对象。这需要在Oauth2中配置，因为在OAuth2中配置了AuthenticationManager，密码验证才会开启。在本例中，采用的是密码验证。

    - authenticationManagerBean: 配置了验证管理的Bean

- UserServiceDetail实现了UserDetailsService，并使用了BCryptPasswordEncoder对密码进行加密。