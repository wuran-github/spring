# 1. Zuul(1.X)
<!-- TOC -->

- [1. Zuul(1.X)](#1-zuul1x)
    - [1.1. 工作原理](#11-工作原理)
    - [1.2. 实战](#12-实战)
        - [1.2.1. 搭建Zuul服务](#121-搭建zuul服务)
        - [1.2.2. 在Zuul上配置API接口的版本号](#122-在zuul上配置api接口的版本号)
        - [1.2.3. 在Zuul上配置熔断器](#123-在zuul上配置熔断器)
        - [1.2.4. 使用过滤器](#124-使用过滤器)
        - [Zuul的常见使用方式](#zuul的常见使用方式)
    - [其他注意事项](#其他注意事项)
        - [如何让服务只让Zuul访问，不让外部访问](#如何让服务只让zuul访问不让外部访问)

<!-- /TOC -->


- Zuul作为路由网关，有6个作用
1. Zuul、Ribbon和eureka结合，实现智能路由和负载均衡。
2. 将所有服务的API接口统一聚合，统一对外暴露。保护内部接口。
3. 可以作用户身份认证和权限认证。
4. 实现监控。
5. 流量监控。
6. 分离API接口，方便测试。
- Zuul Wiki
- https://github.com/Netflix/zuul/wiki
## 1.1. 工作原理
- Zuul是通过Servlet实现的。Zuul通过自定义的ZuulServlet(类似spring mvc的DispatchServlet)来对请求进行控制。
- Zuul包括以下4种过滤器。
    - PRE过滤器:在请求路由到具体服务之前执行的。可以作安全验证，如身份、参数验证。
    - ROUTING过滤器：用于将请求路由到具体的微服务实例。默认情况下使用HttpClient进行网络请求。
    - POST过滤器:请求已被路由到微服务后执行的。一般用作收集统计信息、指标、以及将响应传输到客户端。
    - ERROR过滤器:其他过滤器发生错误时执行。

- Zuul采取了动态读取、编译和运行这些过滤器。过滤器之间不能直接互相通信，通过RequestContext对象来共享数据。每个请求都会创建一个RequestContext对象。Zuul过滤器具有以下关键特性：
    - Type:过滤器的类型
    - Execution Order(执行顺序)：规定了过滤器的执行顺序，Order的值越小，越先执行。
    - Criteria(标准)：Filter执行所需的条件。
    - Action：如果符合条件，就执行Action。

- Zuul的生命周期如下图所示：
    - ![](image/zuulStructure.png)



## 1.2. 实战

### 1.2.1. 搭建Zuul服务
- 创建一个eureka-client项目，引入依赖：
```
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-netflix-zuul</artifactId>
</dependency>
```
- 在启动类上加上@EnableZuulProxy注解开启Zuul功能。

- zuul路由的配置写法。zuul的路由在application.yml中配置。属性是zuul.routes.****
    - zuul.routes是一个`map<String,ZuulRoute>`
    - 结构如下：
    ```
    zuul:
        routes:
            hiapi:
                path: /hiapi/**
                serviceId: eureka-client
            ribbonapi:
                path: /ribbonapi/**
                serviceId: eureka-ribbon-client
    ``` 
    - 它会根据path把对应的路由，例如hiapi，会把/hiapi/开头的URL全部路由到eureka-client服务。
    - 如果指定了serviceId，zuul会自动负载均衡。
    - 如果把serviceId换成固定的url，就不会进行负载均衡
    ```
    zuul:
        routes:
            hiapi:
                path: /hiapi/**
                serviceId: http://localhost:8762
    ```
    - 访问方法是前缀+api接口
    - 如要访问eureka-client的hi接口，路由为/hiapi/hi?name=tee


### 1.2.2. 在Zuul上配置API接口的版本号
- 如果想给每个服务的API接口加前缀，例如v1/hiapi/hi?name=tee
- 需要用到zuul.prefix的配置。
```
zuul.prefix: /v1
```

### 1.2.3. 在Zuul上配置熔断器
- Zuul实现熔断功能需要实现ZuulFallbackProvider的接口。
- 新版本已经换成了FallbackProvider了。
- 该接口有两个方法
    - getRoute方法用于指定熔断功能应用于哪些路由的服务
    - fallbackResponse为进入熔断功能时执行的逻辑。
    - https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/http/client/reactive/ClientHttpResponse.html
- 如果需要所有的路由服务都加熔断功能，只需要getRoute方法返回 `*` 的匹配符。

- 只需要创建一个实现该接口的类即可。同时加上Component注解

- 下面是对eureka-client执行熔断功能的代码：
```
@Component
public class HiFallbackProvider implements FallbackProvider {
    @Override
    public String getRoute() {
        return "eureka-client";
    }

    @Override
    public ClientHttpResponse fallbackResponse(String route, Throwable cause) {
        return new ClientHttpResponse() {
            @Override
            public HttpStatus getStatusCode() throws IOException {
                return HttpStatus.OK;
            }

            @Override
            public int getRawStatusCode() throws IOException {
                return 200;
            }

            @Override
            public String getStatusText() throws IOException {
                return "OK";
            }

            @Override
            public void close() {

            }

            @Override
            public InputStream getBody() throws IOException {
                return new ByteArrayInputStream("error! I am fallback!".getBytes());
            }

            @Override
            public HttpHeaders getHeaders() {
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);
                return headers;
            }
        };
    }
}
```

### 1.2.4. 使用过滤器
- 前面提到过过滤器的作用和种类。
- 实现过滤器只需要继承ZuulFilter，并实现方法即可。
- ZuulFilter有2个抽象方法。
    - filterType 即过滤器的类型。前面提到过有四种类型，分别是
        - pre
        - post
        - routing
        - error
        - 可以使用静态类FilterConstants，里面存储了过滤器类型等常量字符串。

    - filterOrder是过滤顺序，为一个int值，值越小越早执行。
- 他继承了的IZuulFilter接口有2个方法。
    - boolean ShouldFilter 指定该过滤器是否执行过滤逻辑，返回true执行，false不执行
    - Object run 过滤器的过滤逻辑，可以在这里做一些判断，是否执行后面的路由之类的。
        - 注意，是否往下执行可以通过RequestContext的setSendZuulResponse(boolean)来确定，传入false代表不会调用服务接口，直接响应给Client。
        - 返回值一般为null，会被忽视掉。


- 下面是判断请求中是否含有token，没有的话直接返回字符串。
```
@Component
public class TestFilter extends ZuulFilter {
    @Override
    public String filterType() {
        return FilterConstants.PRE_TYPE;
    }

    @Override
    public int filterOrder() {

        return 0;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() throws ZuulException {
        RequestContext requestContext = RequestContext.getCurrentContext();

        HttpServletRequest request = requestContext.getRequest();
        Object token = request.getParameter("token");
        if(token == null){
            requestContext.setSendZuulResponse(false); //不往下传递，直接返回响应
            requestContext.setResponseStatusCode(401);
            try{
                HashMap<String, Object> map = new HashMap<>();
                map.put("status", -1);
                map.put("message", "token is empty");
//                requestContext.getResponse().getWriter().print("token is empty");
                HttpServletResponse response = requestContext.getResponse();
                response.getWriter().print(map);
            }catch(Exception ex) {
            }
        }
        return null;
    }
}
```
- 在实际开发中，可以用此过滤器进行安全验证。

### Zuul的常见使用方式
- Zuul采用了类似Spring MVC的DispatchServlet来实现，采用的是异步阻塞模型，所以性能比Ngnix差。
- 但是Zuul和其他Netflix组件可以互相配合、无缝集成，很容易就能实现负载均衡、智能路由和熔断器等功能，而且大多数情况下Zuul以集群的形式存在的，横向扩展能力非常好。因此当负载过高时，可以通过添加实例来解决性能瓶颈。

- 一种常见的方式时对不同的去到使用不同的Zuul来路由。如移动端共用一个Zuul网关实例，Web端用另一个Zuul网关实例。

## 其他注意事项
- 如果使用zuul网关转发请求，一定要设置sensitiveHeaders为空，该属性用于过滤敏感头部信息，而默认的敏感头部信息包括了Authorization。
```
	/**
	 * List of sensitive headers that are not passed to downstream requests. Defaults to a
	 * "safe" set of headers that commonly contain user credentials. It's OK to remove
	 * those from the list if the downstream service is part of the same system as the
	 * proxy, so they are sharing authentication data. If using a physical URL outside
	 * your own domain, then generally it would be a bad idea to leak user credentials.
	 */
	private Set<String> sensitiveHeaders = new LinkedHashSet<>(
			Arrays.asList("Cookie", "Set-Cookie", "Authorization"));

```

### 如何让服务只让Zuul访问，不让外部访问
- 答案是内网隔离。其他服务不开放端口，都是内网，只开放网关端口为外网。


