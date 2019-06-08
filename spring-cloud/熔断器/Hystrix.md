# Hystrix
- 当某个API的失败次数在一定时间内小于阈值时，熔断器处于关闭状态，该API正常工作。
- 当大于阈值时，Hystrix判断API处于故障状态，打开熔断器。这时候对该API的请求会执行快速失败操作。（即fallback回退的逻辑），不执行业务逻辑，请求的线程不会处于阻塞状态。

- 处于打开状态的熔断器，一段时间会后处于半打开状态，即选择一定数量的请求执行正常逻辑，剩余的请求继续执行快速失败操作。若执行正常逻辑的请求失败了，熔断器继续打开。若成功，熔断器关闭。

## 在restTemplate和ribbon上使用熔断器
1. 加入依赖
```
	<dependency>
	<groupId>org.springframework.cloud</groupId>
	<artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
	</dependency>
```	
2. 开启注解
```
	@EnableHystrix
```

3. 修改Service方法，在方法上加上HystrixCommand
    - HYstrix的fallbackMethod属性指定了一个回退逻辑的方法。在熔断器打开的状态下，会执行fallback逻辑。
    - fallback逻辑最好是返回一些静态的字符串，必须要处理复杂的逻辑/也不需要原成调度其他服务。这样方便执行快速失败，释放线程资源
```
@HystrixCommand(fallbackMethod = "hiError")
public String hi(String name){
    return restTemplate.getForObject("http://eureka-client/hi?name="+name, String.class);
}
```

- 这时候如果访问的api出现问题，就会跳转到fallback函数。

## 在feign上使用熔断器

- feign的依赖中已经引入了Hystrix的依赖，因此不需要引入新的依赖。

- 在配置中开启Hystrix的功能：application.yml
```
feign:
    hystrix:
        enabled:true
```

- 在feignClient的注解上配置加上快速失败的处理类，该处理类是作为Feign熔断器的逻辑处理类，必须实现被@FeignClient修饰的接口。
    - fallback属性加上处理类
```
@FeignClient(value = "eureka-client",
        configuration = FeignConfig.class,
        fallback = HiErrorHandler.class)
public interface EurekaClientFeign {
    @GetMapping("hi")
    String sayHiFromEurekaClient(@RequestParam("name") String name);
}
```

- 处理类实现接口，同时加上@Component，交给spring容器管理。
```
@Component
public class HiErrorHandler implements EurekaClientFeign {
    @Override
    public String sayHiFromEurekaClient(String name) {
        return "is error" + name;
    }
}
```

- 这样当服务不可用时就会自动调用处理类。


