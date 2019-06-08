# Zuul(1.X)

- Zuul作为路由网关，有6个作用
1. Zuul、Ribbon和eureka结合，实现智能路由和负载均衡。
2. 将所有服务的API接口统一聚合，统一对外暴露。保护内部接口。
3. 可以作用户身份认证和权限认证。
4. 实现监控。
5. 流量监控。
6. 分离API接口，方便测试。
- Zuul Wiki
- https://github.com/Netflix/zuul/wiki
## 工作原理
- Zuul是通过Servlet实现的。Zuul通过自定义的ZuulServlet(类似spring mvc的DispatchServlet)来对请求进行控制。
- Zuul包括以下4种过滤器。
    - PRE过滤器:在请求路由到具体服务之前执行的。可以作安全验证，如身份、参数验证。
    - ROUTING过滤器：用于将请求路由到具体的微服务实例。默认情况下使用HttpClient进行网络请求。
    - POST过滤器:请求已被路由到微服务后执行的。一般用作收集统计信息、指标、以及将响应传输到客户端。
    - ERROR过滤器:其他过滤器发生错误时执行。

- Zuul采取了动态读取、编译和运行这些过滤器。过滤器之间不能直接互相通信，通过RequestContext对象来共享数据。每个请求都会创建一个RequestContext对象。Zuul过滤器具有以下关键特性：
    - Type:过滤器的类型
    - Execution Order(执行顺序)：规定了过滤器的执行四混徐，Order的值越小，越先执行。
    - Criteria(标准)：Filter执行所需的条件。
    - Action：如果符合条件，就执行Action。

- Zuul的生命周期如下图所示：
    - ![](image/zuulStructure.png)




