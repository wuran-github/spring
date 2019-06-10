# 1. Spring Security

<!-- TOC -->

- [1. Spring Security](#1-spring-security)
    - [1.1. Spring Security提供的安全模块](#11-spring-security%E6%8F%90%E4%BE%9B%E7%9A%84%E5%AE%89%E5%85%A8%E6%A8%A1%E5%9D%97)
    - [1.2. Spring Boot Security案例](#12-spring-boot-security%E6%A1%88%E4%BE%8B)
        - [1.2.1. 构建Spring boot Security工程](#121-%E6%9E%84%E5%BB%BAspring-boot-security%E5%B7%A5%E7%A8%8B)
            - [1.2.1.1. POM依赖](#1211-pom%E4%BE%9D%E8%B5%96)
        - [1.2.2. 配置Spring Security](#122-%E9%85%8D%E7%BD%AEspring-security)
            - [1.2.2.1. 配置WebSecurityConfigurerAdapter](#1221-%E9%85%8D%E7%BD%AEwebsecurityconfigureradapter)
            - [1.2.2.2. 配置HttpSecurity](#1222-%E9%85%8D%E7%BD%AEhttpsecurity)
- [深入](#%E6%B7%B1%E5%85%A5)
    - [关于自定义登录问题](#%E5%85%B3%E4%BA%8E%E8%87%AA%E5%AE%9A%E4%B9%89%E7%99%BB%E5%BD%95%E9%97%AE%E9%A2%98)
        - [过滤链](#%E8%BF%87%E6%BB%A4%E9%93%BE)

<!-- /TOC -->
- Spring Security(下称SS)是Spring的一个安全组件。
- SS采用 "安全层" 的概念，使每一层都尽可能安全，连续的安全层可以达到全面的防护。
- SS可以在Controller层、Service层、DAO层等以加注解的方式来保护应用程序的安全。
- SS提供了细粒度的权限控制，可以精细到每一个API接口、每一个业务的方法。

## 1.1. Spring Security提供的安全模块
- 在安全验证方面， SS提供了很多的安全验证模块。大部分的验证模块来自第三方的权威机构。
    - HTTP BASIC 头认证
    - HTTP Digest 头认证
    - HTPP X.509客户端证书交换认证
    - LDAP
    - 基于表单的认证
    - OpenID验证
    - 基于预先建立的请求头的验证
    - CAS
    - 远程方法调用(RMI)和HttpInvoker的认证
    - 自动 记住我的身份验证
    - 匿名验证
    - Run-as身份验证(每一次调用都需要提供身份标识)
    - Java认证和授权服务
    - Java EE 容器认证
    - Kerberos
    - Java开源的单点登录
    - OpenNMS网络管理平台
    - AppFuse
    - AndroMDA
    - Mule ESB
    - Direct Web Request
    - Grails
    - Tapestry
    - JTrac
    - Jasypt
    - Roller
    - Elastic Path
    - Atlassina Crowd
    - 自己创建的认证系统

## 1.2. Spring Boot Security案例

### 1.2.1. 构建Spring  boot Security工程

#### 1.2.1.1. POM依赖
- 需要如下几个依赖：
```
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
```

### 1.2.2. 配置Spring Security

#### 1.2.2.1. 配置WebSecurityConfigurerAdapter
- 创建完工程后，需要配置SS。新建一个SecurityConfig类，作为配置类。
- 作为配置类，它继承WebSecurityConfigurerAdapter类。
- 加上@EnableWebSecurity注解，开启WebSecurity的功能。
- 注入AuthenticationManagerBuilder类的Bean。
```
@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password("123456")
                .roles("USER");
    }
}
```
- 上述代码做了Spring Security的基本配置，并通过AuthenticationManagerBuilder在内存中创建了一个认证用户的信息。该用户名为user，密码为123456，有USER的角色。
- 代码虽少，但是做了很多安全防护的工作，包括：
    - 应用的每一个请求都需要认证
    - 自动生成一个登陆表单
    - 可以用username和password认证
    - 用户可以注销
    - 组织了CSRF攻击
    - Session Fixation保护
    - 安全Header集成了以下内容。

#### 1.2.2.2. 配置HttpSecurity
- WebSecurityConfigurerAdapter配置了如何验证用户信息。
- 而HttpSecurity负责配置以下部分:
    - 哪些用户需要身份验证
    - 是否支持基于表单的验证
    - 哪些资源需要验证

- 新建一个SecurityConfig类继承WebSecurityConfigurerAdapter作为HttpSecurity的配置类。
- 可以使用上面新建的类。

- 通过复写configure(HttpSecurity)方法来配置HttpSecurity。
```
 @Override
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
            .antMatchers("/css/**","/index").permitAll()
            .antMatchers("/user/**").hasRole("USER")
            .antMatchers("/blogs/**").hasRole("USER")
            .and()
            .formLogin().loginPage("/login").failureUrl("/login-error")
            .and()
            .exceptionHandling().accessDeniedPage("/401");

}
```
- 上述代码比较好懂
    - antMatchers是要匹配的API，可以传入多个String类型
    - permitAll代表不需要验证，可以直接访问
- 代码采用链式编码，每次hasRole或permitAll等方法都会返回一个ExpressionInterceptUrlRegistry，代表前面的API已经处理，可以重新处理新的API。
- and返回一个HttpSecurity，可以做其他新的操作。
- formLogin 使用表单登录方式，还有openid和Oauth2的方式。



# 深入

## 关于自定义登录问题
- 我们可以看到，Spring Security的登录部分的认证是内部实现的，不需要我们写逻辑，只需要我们指定登录的路由，同时把表单提交到该路由即可。
- 但是如果我们希望实现自己的逻辑该怎么做？例如我们希望除了用户名和密码，还要加上验证码等消息呢？
- 经过网上查阅和结构分析，大概有如下几个地方可以做文章：
    1. 过滤链，FilterChain，这是网上普遍的做法，在登录过滤器之前加一个自定义的过滤器拦截，在里面做逻辑判断。
    2. SuccessHandler ，成功后跳转的处理器，看看是否能在这里做文章。
    3. UsernamePasswordAuthenticationFilter，这是验证的过滤器，看看是否可以重写或继承该类来实现自己的验证逻辑。

### 过滤链
- SS的过滤器形成了一条过滤链，一个一个往下执行，我们可以在UsernamePasswordAuthenticationFilter之前加上一个过滤器，在该过滤器中做一些操作，然后决定是否往下继续执行后续的过滤链。
```
public class CodeAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private boolean isOpenValidateCode = true;
    private String mockCode = "1234";
    public CodeAuthenticationFilter(String pattern){
        //指定请求地址，拦截哪个URL
        super(new AntPathRequestMatcher(pattern, "POST"));
        //获取失败处理器
        SimpleUrlAuthenticationFailureHandler failureHandler = (SimpleUrlAuthenticationFailureHandler)getFailureHandler();

        //失败后跳转到指定页面
        failureHandler.setDefaultFailureUrl("/error");
        //也可以指定自定义的失败处理器，做其他操作，如前后端分离
//        setAuthenticationFailureHandler(failureHandler);
    }

    /**
     * 这是过滤链执行的主要函数
     * @param req
     * @param res
     * @param chain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        //获取到request和response,就可以取出表单的内容了
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        //可以获取到session传递一些信息

        HttpSession session = request.getSession();

        if(isOpenValidateCode) {
            String code = request.getParameter("code");
            if(validateCode(code)){
                
            }
            else{
                session.setAttribute("errorMsg", "code Error");
                return;
            }
        }
        //继续执行过滤链的下一个过滤器
        chain.doFilter(req, res);

    }

    /**
     * 验证函数
     * @param code
     * @return
     */
    private boolean validateCode(String code){
        return mockCode.equals(code);
    }
    /**
     * 尝试认证
     * 影响到DoFilter是否往下执行，有3个可能的情况
     * 1. 返回Authentication，代表认证完成，不会继续往下执行
     * 2. 过程中抛出AuthenticationException异常，代表认证异常
     * unsuccessfulAuthentication会被执行
     * 3. 返回null,代表认证还没结束，会继续往下执行认证过程
     * @param httpServletRequest
     * @param httpServletResponse
     * @return
     * @throws AuthenticationException
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
        return null;
    }
}

```
- 主要有几点：
1. 在构造器中指定拦截哪个URL
2. 指定失败处理器或失败跳转URL
3. 编写doFilter逻辑，决定是否往下传递过滤
4. 编写attemptAuthentication函数，决定当前认证是否已经完整。

- 参考网址：https://www.cnblogs.com/MrSi/p/8032936.html
