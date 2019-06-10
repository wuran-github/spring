# 1. Spring Cloud Config
<!-- TOC -->

- [1. Spring Cloud Config](#1-spring-cloud-config)
    - [1.1. Config Server从本地读取配置文件](#11-config-server%E4%BB%8E%E6%9C%AC%E5%9C%B0%E8%AF%BB%E5%8F%96%E9%85%8D%E7%BD%AE%E6%96%87%E4%BB%B6)
        - [1.1.1. 构建config Server](#111-%E6%9E%84%E5%BB%BAconfig-server)
        - [1.1.2. 构建Config Client](#112-%E6%9E%84%E5%BB%BAconfig-client)
    - [1.2. 从远程仓库读取](#12-%E4%BB%8E%E8%BF%9C%E7%A8%8B%E4%BB%93%E5%BA%93%E8%AF%BB%E5%8F%96)
    - [1.3. 构建高可用的Config Server](#13-%E6%9E%84%E5%BB%BA%E9%AB%98%E5%8F%AF%E7%94%A8%E7%9A%84config-server)
        - [1.3.1. 改造Config Server](#131-%E6%94%B9%E9%80%A0config-server)
        - [1.3.2. 改造Config Client](#132-%E6%94%B9%E9%80%A0config-client)
    - [1.4. 使用Spring cloud bus刷新配置](#14-%E4%BD%BF%E7%94%A8spring-cloud-bus%E5%88%B7%E6%96%B0%E9%85%8D%E7%BD%AE)

<!-- /TOC -->
- Config Server可以从本地仓库读取配置文件，也可以从远程Git仓库读取。
- 本地仓库是指将所有的配置文件统一写在Config Server工程目录下。Config Server暴露Http API接口，Config Client通过调用Config Server的Http API接口来读取配置文件。

## 1.1. Config Server从本地读取配置文件

### 1.1.1. 构建config Server
- POM依赖：
```
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-config-server</artifactId>
</dependency>
```

- application.yml
```
server:
  port: 8769
spring:
  application:
    name: eureka-client
  cloud:
    config:
      server:
        native:
          search-locations: classpath:/shared
  profiles:
    active: native
```

- 启动类加上EnableConfigServer注解

- 在Resources目录下新建一个shared目录，存放本地配置文件。新建一个config-client-dev.yml配置我呢见，指定程序端口号为8790，定义一个变量foo。
```
server:
  port: 8790

foo: foo version 1
```

### 1.1.2. 构建Config Client
- POM依赖:
```
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-config</artifactId>
</dependency>
```

- 使用bootstrap.yml做配置。bootstrap.yml启动顺序比application.yml要靠前。
    - 在bootstrap.yml中指定了程序名为config-client，向指定的uri地址的Config Server读取配置文件。
        - 注意，是uri，不是url
    - 如果没有读取成功，则执行快速失败。读取的是dev文件。
    - bootstrap.yml配置文件中的变量`{spring.application.name}`和变量`{spring.profiles.active}`，两者以 - 相连，成狗了向Config Server读取的配置文件名。
```
server:
  port: 8790

spring:
  application:
    name: config-client

  cloud:
    config:
      uri : http://localhost:8769
      fail-fast: true

  profiles:
    active: dev
```
- 注意，不要建立application.yml文件，否则的话会再去读取application.yml文件，一些属性会被覆盖。

- 然后就可以试着创建一个接口来访问配置的foo变量。
- 其实看端口就已经知道读取配置成功了，因为在该项目中我们没有设置端口，而是在config server的配置中设置了，启动后端口与设置文件一致。
```
@RestController
public class FooController {
    @Value("${foo}")
    String foo;
    @GetMapping("foo")
    public String getFoo(){
        return foo;
    }
}
```

## 1.2. 从远程仓库读取
- spring cloud config支持从git仓库读取。
- 其实就是把本地文件夹挪到了远程仓库。

- applciation的配置文件如下：
    - 注意uri去掉.git后缀
    - search-paths是要搜索的文件夹地址
    - username和password为git仓库的登录名和密码。如果是公开仓库则不需要
    - label是git仓库的分支。
    - 注意，配置远程连接的话profiles的active属性必须设置为remote值。
```
server:
  port: 8769
spring:
  application:
    name: config-server
  cloud:
    config:
      server:
        #远程仓库
        git:
          uri: https://github.com/wuran-github/config-server.git
          search-paths: configs
          #username: wuran-github
          #password:
          default-label: master
        # 本地文件夹
        #native:
        #  search-locations: classpath:/shared
      label: master
  profiles:
    #远程需要配置为remote
    active: remote
    #本地则是native
    #active: native

```

- 然后就可以连接远程仓库读取配置文件了。

## 1.3. 构建高可用的Config Server
- 当服务很多都需要同时从配置中心Config Server读取配置文件时，我们可以将配置中心做成一个微服务，并集群化。

### 1.3.1. 改造Config Server
- 把Config Server改造成一个微服务。加入POM起步依赖，以及加上EnableEurekaClient注解。

- 设置application的配置
```
eureka:
  client:
    service-url:
        defaultZone:
          http://localhost:8761/eureka/
```

### 1.3.2. 改造Config Client
- 依旧是改造成一个eureka client。加入POM起步依赖，以及EnableEurekaClient注解。

- 设置bootstrap.yml的配置
    - 使用服务发现来找configserver需要配置spring.cloud.discoviery
    - service-id 是config server的服务名
    - enabled true
```
eureka:
  client:
    service-url:
        defaultZone:
          http://localhost:8761/eureka/
spring:
  application:
    name: config-client

  cloud:
    config:
      #uri : http://localhost:8769
      fail-fast: true
      discovery:
        service-id: config-server
        enabled: true
  profiles:
    active: dev

```

## 1.4. 使用Spring cloud bus刷新配置
- bus(总线)可以为微服务做监控，实现应用程序之间的通信。
- spring cloud bus 可选的消息代理组件包括RabbitMQ,AMQP和Kafka等。

- 使用bus可以不需要每个服务重新启动就可以更新配置项。十分方便。

- 使用bus