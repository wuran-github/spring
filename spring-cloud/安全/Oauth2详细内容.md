# Oauth2详细内容
## 自定义授权模式
- Oauth2提供了自带的四种授权模式，但是有时候我们需要额外的授权模式
- 例如微信登录，我们可能需要通过openid的形式登录
- 自定义授权模式的关键是要自定义令牌授予者，AbstractTokenGranter，通过这个来授予令牌。
- 

## /oauth/token 获取token的过程

- Oauth2获取token的Api是`/oauth/token`， 其源码类为TokenEndpoint
- 我们一起来看看这个类做了什么，模仿这个类作一个自己的token认证器。


## token验证过滤器
- sso使用JWT模式时的token验证过滤器是OAuth2AuthenticationProcessingFilter，在这里面验证了token。
- 如果我们希望对用户是否审核进行判断，就需要在此之前自己加一个过滤器。

## access_token的携带方法
- 可以在header中带
- 也可以url参数中带
```
protected String extractToken(HttpServletRequest request) {
		// first check the header...
		String token = extractHeaderToken(request);

		// bearer type allows a request parameter as well
		if (token == null) {
			logger.debug("Token not found in headers. Trying request parameters.");
			token = request.getParameter(OAuth2AccessToken.ACCESS_TOKEN);
			if (token == null) {
				logger.debug("Token not found in request parameters.  Not an OAuth2 request.");
			}
			else {
				request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, OAuth2AccessToken.BEARER_TYPE);
			}
		}

		return token;
	}
```