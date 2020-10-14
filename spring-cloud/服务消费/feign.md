# Feign

- Feign用于消费服务，可以多次重试。

## 配置

### POM依赖
- Feign包括了Ribbon和Hystrix的依赖，因此只需要引入openFeign即可。
```
 <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-openfeign</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

```

### 启动类
- 在启动类上加入注解EnableFeignClients

### config
- 创建一个FeignConfig类，结构如下：
```
@Configuration
public class FeignConfig {
    /**
     * 用于远程调用失败后重试
     *
     * @return
     */
    @Bean
    public Retryer feignRetryer(){
        return new Retryer.Default(100,SECONDS.toMillis(1),5);
    }
}
```