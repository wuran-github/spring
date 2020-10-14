# 1. Spring Cloud OAuth2
<!-- TOC -->

- [1. Spring Cloud OAuth2](#1-spring-cloud-oauth2)
    - [1.1. Spring OAuth2](#11-spring-oauth2)
        - [1.1.1. OAuth2 Provider](#111-oauth2-provider)
            - [1.1.1.1. Authorization Server 配置](#1111-authorization-server-配置)
            - [1.1.1.2. Resource Server 的配置](#1112-resource-server-的配置)
        - [1.1.2. OAuth2 Client](#112-oauth2-client)
            - [1.1.2.1. Protected Resource Configuration](#1121-protected-resource-configuration)
            - [1.1.2.2. Client Configuration](#1122-client-configuration)
    - [1.2. 案例分析](#12-案例分析)
        - [1.2.1. Eureka Server](#121-eureka-server)
        - [1.2.2. Uaa授权服务](#122-uaa授权服务)
            - [1.2.2.1. pom依赖](#1221-pom依赖)
            - [1.2.2.2. application.yml](#1222-applicationyml)
            - [1.2.2.3. 配置Spring Security](#1223-配置spring-security)
            - [1.2.2.4. 配置Authorization Server](#1224-配置authorization-server)
            - [1.2.2.5. 暴露Remote Token Service接口](#1225-暴露remote-token-service接口)
            - [1.2.2.6. 获取Token](#1226-获取token)
        - [1.2.3. 编写service-hi 资源服务](#123-编写service-hi-资源服务)
            - [项目依赖](#项目依赖)
            - [application配置文件](#application配置文件)
            - [配置Resource Server](#配置resource-server)
            - [配置OAuth2 Client](#配置oauth2-client)
            - [编写用户注册接口](#编写用户注册接口)
        - [小结](#小结)
            - [hasRole和hasAuthority的区别](#hasrole和hasauthority的区别)
            - [token刷新问题](#token刷新问题)

<!-- /TOC -->
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

## 1.1. Spring OAuth2
- Spring中的Spring Oauth2(下面简称SO)实现了Oauth2。SO分为两部分，分别是OAuth2 Provider(下面简称OP)和OAuth2 Client(下面简称OC)。

### 1.1.1. OAuth2 Provider
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

#### 1.1.1.1. Authorization Server 配置
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

#### 1.1.1.2. Resource Server 的配置
- RS提供了受OAuth2保护的资源，这些资源为API接口、HTML页面，JS文件等。
- SO提供了实现此保护功能的的SS认证过滤器。
- 在加了@Configuration注解的配置类上加@EnableResourceServer注解，开启RS的功能，并使用ResourceServerConfigurer继续配置，需要配置以下的内容：
    - tokenServices: 定义Token Service。
        - 例如用ResourceServerToeknservices类，配置Token是如何编码和解码的。
        - 如果RS和AS在同一个工程内则不需要配置，否则需要配置。
        - 可以用RemoteTokenServices类，即RS采用远程授权服务器进行Token解码，这时也不需要配置此选项。
    - resourceId: 资源Id.


### 1.1.2. OAuth2 Client
- OC用于访问被OA保护起来的资源，客户端需要提供用于存储用户的授权码和访问令牌的机制，需要配置如下2个选项：
    - Protected Resource Configuration(受保护资源配置)
    - Client Configuration(客户端配置)

#### 1.1.2.1. Protected Resource Configuration
- 使用OAuth2ProtectedResourceDetails类型的Bean来定义受保护的资源，受保护的资源具有以下属性：
    - Id: 资源的Id，在SO中没用到，不需要配置，默认即可。
    - clientId: OC的Id，和之前OP的配置一一对应。
    - clientSecret: 客户端密码，和OP的配置对应。
    - accessTokenUri: 获取Token的API节点。
    - scope: 客户端的域。
    - clientAuthenticationScheme: 两种客户端验证类型，分别为Http Basic和Form。默认前者。
    - userAuthorizationUri: 如果用户需要授权访问资源，则用户被重定向到的认证Uri。


#### 1.1.2.2. Client Configuration
- 对于OC的配置，可以使用@EnableOAuth2Client注解来简化配置。另外还需要配置以下两项：
    - 创建一个过滤器Bean(Bean的Id为oauth2ClientContextFilter)，用来存储当前请求和上下文的请求。在请求期间，如果用户需要进行身份验证，则用户会被重定向到OAuth2的认证URI。
    - 在Request域内创建AccessTokenRequest类型的Bean。

---
## 1.2. 案例分析
- 首先看架构，分别由3个工程，服务注册中心eureka-server，授权中心Uaa工程auth-service和资源中心service-hi。

1. 浏览器向auth-service服务器提供客户端信息、用户名和密码，请求获取Token。
2. auth-service确认无误后，根据信息生成Token返回给浏览器。
3. 浏览器在以后的每次请求都携带Token给资源服务service-hi。
4. 资源服务获取到请求携带的Token后，通过远程调度将Token给授权服务auth-service确认。
5. auth-service确认Token正确无误后，将该Token对应的用户权限信息返回给资源服务。
6. 如果该Token对应的用户具有访问该API接口的权限，就正常返回请求，否则返回权限不足的错误。

### 1.2.1. Eureka Server
- 和前面描述的一样


### 1.2.2. Uaa授权服务
#### 1.2.2.1. pom依赖
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

#### 1.2.2.2. application.yml
- 内容如下：
```
server:
  port: 5000
  servlet:
    context-path: /uaa #所有路由加上该前缀 部署后似乎无效，因此最好还是不要加前缀

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

#### 1.2.2.3. 配置Spring Security
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

#### 1.2.2.4. 配置Authorization Server
- 在启动类上加上@EnablefResourceServer注解，开启Resource Server。程序需要对外暴露获取Token的API接口和验证Token的API接口，所以该程序也是一个资源服务。
    - 注意书上代码有很严重的错误，它使用了dataSource来在声明时初始化TokenStore，我们知道赋值操作是在构造器之前，而构造器之后Spring才开始注入依赖，所以这一步赋值操作时dataSource必然为空。
    - 因此需要实现InitializingBean接口，在spring容器初始化后再初始化TokenStore
```
@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationConfig
        extends AuthorizationServerConfigurerAdapter implements InitializingBean {
    @Autowired
    private DataSource dataSource;
    //        private TokenStore tokenStore = new InMemoryTokenStore();
    //书上代码这里有很重大的错误，不能这样初始化
    //private JdbcTokenStore tokenStore = new JdbcTokenStore(dataSource);
    private JdbcTokenStore tokenStore;
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("browser")
                .authorizedGrantTypes("refresh_token","password")
                .scopes("ui")
                .and()
                .withClient("service-hi")
                //原版这里是明文，现在必须加密了
                .secret(passwordEncoder().encode("123456"))
                .authorizedGrantTypes("client_credentials", "refresh_token", "password")
                .scopes("server");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .tokenStore(tokenStore)
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Override
    public void afterPropertiesSet() throws Exception {
        tokenStore = new JdbcTokenStore(dataSource);
    }
}
```
- OAuth2AuthorizationConfig 继承AuthorizationServerConfigurerAdapter，并在这个类上加上注解@EnableAuthorizationServer，开启授权服务功能。
- 作为授权服务需要配置3个选项，分别是
    - ClientDetailsServiceConfigurer
    - AuthorizationServerEndpointsConfigurer
    - AuthorizationServerSecurityConfigurer

- ClientDetailsServiceConfigurer配置了客户端的一些基本信息。
    - clients.inMemory方法配置了将客户端的信息存储在内存中
    - withClient("browser")方法创建了一个clientId为borwser的客户端。
    - authorizedGrantTypes("refresh_token", "password")方法配置了验证类型为refresh_token和password。
    - scopes("ui")方法配置了客户端域为"ui"
    - 接着创建了另一个client，id为"service-hi"


- AuthorizationServerEndpointsConfigurer需要配置tokenStore authenticationManager和UserDetailsService。
    - tokenSotre(Token的存储方式)采用将Token存储在内存中，即InMemoryTokenStore。如果资源服务和授权服务是同一个服务，用InMemoryTokenStore是最好的选择。如果不是，则不用。因为当授权服务出现故障，需要重启服务时，之前存在内存中的Token会全部丢失，导致资源服务的Token全部失效。
    - 另一种方法是用JdbcTokenStore，用数据库去存储。使用JdbcTokenStore存储需要引入连接数据库依赖，如本例的MySQL连接去，JPA，而且要初始化数据库脚本。也可以用Redis等内存数据库。
    - authenticationManager这个Bean是用来开启密码类型的验证的。
    - UserDetailsService用来读取验证用户的信息。

- AuthorizationServerSecurityConfigurer配置了获取Token的策略，
    - 在本例中对获取Token的请求不进行拦截，只需要验证获取Token的验证信息，这些信息无误就返回Token。
    - 另外配置了检查Token的策略。

- 同时必须配置加密策略，注入一个密码加密策略Bean，令牌的口令也许使用同样的密码加密策略进行加密：
```
@Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
.secret(passwordEncoder().encode("123456"))
```

#### 1.2.2.5. 暴露Remote Token Service接口
- 本例采用RemoteTokenServices这种方法对Token进行验证。如果其他资源服务需要验证Token，则需要远程调用授权服务暴露的验证Token的API接口。本案例中验证Token的API接口的代码如下：
```
@RestController
@RequestMapping("/user")
public class UserController {
    @RequestMapping(value = "current", method = RequestMethod.GET)
    public Principal getUser(Principal principal){
        return principal;
    }
}
```

#### 1.2.2.6. 获取Token
- 启动auth-service服务，可以使用ajax或postman获取Token。
- 获取Token的API接口使用了基本认证(Http Basic Authentication)。
- 基本认证是一种用来允许客户端程序在请求时提供用户名和口令形式的身份凭证来验证客户端的。用户名和口令形式的身份凭证是在用户名后追加一个冒号，然后串接上口令，将拼接后的字符串用Base64算法编码得到的。
- 如本案例中的service-hi，口令123456，组合后得到service-hi:123456。Base64加密后：`c2VydmljZS1oaToxMjM0NTY=`
- 后台获取后会进行解密，拿出口令，然后用定义的加密算法加密后再进行比对。
- 使用ajax请求Token的方式是在headers中添加相关内容。
```
url: domain:host/uaa/oauth/token
headers:{'Authorization': 'Basic c2VydmljZS1oaToxMjM0NTY='}
data{
    username:
    password:
    grant_type:'password'
}

```
- 向后端发送请求，返回成功：
```
{
    "access_token": "9ddcd8a1-72c8-4930-b77d-10a4ff0f8a04",
    "token_type": "bearer",
    "refresh_token": "4c76b69c-ddde-4dad-a697-5cb64dd09a3b",
    "expires_in": 43030,
    "scope": "server"
}
```
- 第一次发送时，控制台会打印一条info，提示Failed to find access token for token，后台这时候会创建一条token存储到数据库。
- 注意，access_token是权限token
- refresh_token是刷新token，用于刷新当前token的。

- 拿到的Token的使用方法：在用户访问受保护资源时，在请求的Header中加上参数名为：Authorization，参数值为 "Bearer {Token}"的参数。

### 1.2.3. 编写service-hi 资源服务
- 有了授权服务，下面我们开始编写资源服务。

#### 项目依赖
- 创建一个service-hi，引入需要的依赖：
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
            <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-oauth2</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-openfeign</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-security</artifactId>
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

#### application配置文件
- 在配置文件中，配置了程序名，端口，服务注册中心地址，数据库等内容。
- 资源服务相关的有security.oauth2.resource.user-info-uri:，指定获取当前Token的用户信息，配置了client的相关信息，这些配置和Uaa服务中的配置一一对应。
```
server:
  port: 8762

eureka:
  client:
    service-url:
        defaultZone:
          http://localhost:8761/eureka/
spring:
  application:
    name: service-hi
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
security:
  oauth2:
    resource:
      user-info-uri: http://localhost:5000/uaa/user/current
    client:
      client-id: service-hi
      client-secret: 123456
      access-token-uri: http://localhost:5000/uaa/oauth/token
      grant-type: client_credentials, password
      scope: server


```

#### 配置Resource Server
- service-hi作为Resource Server，需要配置Resource Server的相关配置：
```
@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/user/registry").permitAll()
                .anyRequest().authenticated();
    }
}
```
- 再ResourceServerConfig类上加@EnableResourceServer，开启Resource server的功能。加EnableGlobalMethodSecurity开启方法级别的保护。
- 重写configure(HttpSecurity)，配置哪些请求需要验证，哪些不需要。

#### 配置OAuth2 Client
- OAuth2 Client用来访问被OAuth2保护的资源。
- service-hi作为OAuth2 Client，它的配置代码如下：
```
@Configuration
@EnableOAuth2Client
@EnableConfigurationProperties
public class OAuth2ClientConfig {
    @Bean
    @ConfigurationProperties(prefix = "security.oauth2.client")
    public ClientCredentialsResourceDetails clientCredentialsResourceDetails(){
        return new ClientCredentialsResourceDetails();
    }
    @Bean
    public RequestInterceptor oauth2FeignRequestInterceptor(){
        return new OAuth2FeignRequestInterceptor(
                new DefaultOAuth2ClientContext(),
                clientCredentialsResourceDetails());
    }

    @Bean
    public OAuth2RestTemplate clientCredentialsRestTemplate(){
        return new OAuth2RestTemplate(clientCredentialsResourceDetails());
    }
}
```
- @ConfigurationProperties的作用类似于@Value，可以把配置文件的值注入到对象中。
- 简单来说，需要配置3个选项：
    - 配置受保护的资源的信息，即ClientCredentialsResourceDetails
    - 配置一个过滤器，存储当前请求和上下文
    - 在Reuqest域内创建AccessTokenRequest类型的Bean。

- 使用EnableOAuth2Client注解，开启OAuth2 Client的功能
- 配置一个ClientCredentialsResourceDetails类型的Bean，通过读取配置文件中前缀为security.oauth2.client的配置来获取Bean的配置属性
- 注入一个OAuth2FeignRequestInterceptor类型过滤器的Bean
- 注入一个用于向Uaa服务请求的OAuth2RestTemplate类型的Bean。

#### 编写用户注册接口
- 实际上资源服务的用户不需要和授权服务的表一致，只需要用户名和密码一致即可，毕竟都是去授权服务拿Token。
```
@Entity(name = "service_user")
public class User implements  Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(name = "user_name")
    String username;
    @Column(name = "password")
    String password;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public User() {

    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
```
- 编写一个测试Controller，有3个接口，第一个接口hi不需要任何权限，只需要Header中的Token正确即可。
- 第二个接口需要ADMIN权限
    - 注意hasRole和hasAuthority的区别，前者要求权限字段必须有ROLE_开头
- 第三个接口获取用户当前Token信息。
```
@RestController
public class HiController {
    /** logger */
    private final static Logger LOGGER  = LoggerFactory.getLogger(HiController.class);
    @Value("${server.port}")
    String port;

    @RequestMapping("hi")
    public String home(){
        return "hi, i am "+ port;
    }
    @PreAuthorize("hasRole('ROLE_USER')")
    @RequestMapping("hello")
    public String hello(){
        return "hello, i am "+ port;
    }
    @PreAuthorize("hasRole('ROLE_USER')")
    @RequestMapping("role_user")
    public String role_user(){
        return "role_user";
    }
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping("role_admin")
    public String role_admin(){
        return "role_admin";
    }
    @PreAuthorize("hasRole('USER')")
    @RequestMapping("users")
    public String user(){
        return "user";
    }
    @PreAuthorize("hasRole('ADMIN')")
    @RequestMapping("admin")
    public String admin(){
        return "admin";
    }
    @PreAuthorize("hasAuthority('USER')")
    @RequestMapping("helloUser")
    public String helloUser(){
        return "hello user, i am "+ port;
    }
    @GetMapping("/getPrinciple")
    public OAuth2Authentication getPrinciple(OAuth2Authentication oAuth2Authentication,
    Principal principal,
    Authentication authentication){

        return oAuth2Authentication;
    }
}
```



### 小结
####  hasRole和hasAuthority的区别
- hasRole的数据库字段必须以ROLE开头
    - 即例如数据库存储了USER，那么你用hasRole函数无论如何都没有访问权限
    - 数据库中必须存取ROLE_USER，才能有权限访问
    - 这时候你的参数可以是USER也可以是ROLE_USER
- hasAuthority则不需要ROLE开头，实打实的字符串
    - 数据库中是USER，参数就是USER
    - 是ROLE_USER，参数就是ROLE_USER

#### token刷新问题
- 如果你改变了角色的权限，必须使用refresh_token去刷新token，获取最新的用户信息
- 刷新URL：/oauth/token
- 依旧是Header加上； Basic 64编码(clientId:secret)
- 参数是:
```
refresh_token: 之前获取的fresh_token
grant_type:refresh_token
```
