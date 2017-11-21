package com.kb.claim.filter;

import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.kb.claim.service.RedisService;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class AuthFilter extends ZuulFilter {
	private final String KEY="test7786df7fc3a34e26a61c034d5ec8245d";
	private Set<String> ignoreUri = new HashSet<String>();
	{
		ignoreUri.add("/auth/user/login");
		ignoreUri.add("/auth/user/refreshToken");
	}
	
	
	private static Logger log = LoggerFactory.getLogger(AuthFilter.class);

	@Override
	public String filterType() {
		return "pre";
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
	public Object run() {
		test();
		
		RequestContext ctx = RequestContext.getCurrentContext();
		HttpServletRequest request = ctx.getRequest();
		log.info(String.format("%s >>> %s", request.getMethod(), request.getRequestURL().toString()));
		// Object accessToken = request.getParameter("token");
		String accessToken = request.getHeader("token");
		if(null==accessToken){
			accessToken = request.getParameter("token");
		}

		log.info(String.format("send %s request to %s", request.getMethod(), request.getRequestURL().toString()));

		String uri = request.getRequestURI().toString();
		if (!ignoreUri.contains(uri)  ) {

			byte[] encodedKey = Base64.decodeBase64(KEY);
			SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
			try {
				Claims claims = Jwts.parser().setSigningKey(key).parseClaimsJws(accessToken).getBody();

			} catch (Exception e) {
				ctx.setSendZuulResponse(false);
				ctx.setResponseStatusCode(401);
				try {
					ctx.getResponse().getWriter().write(e.getMessage());
				} catch (Exception e1) {
				}
				
			}

			return null;
		}
		return null;
	}
	
	@Autowired
    private RedisService redisService;
	private void  test(){
		System.out.println("进入了方法");
        String string= redisService.get("key1").toString();
        System.out.println(string);
        //return string;
    }
	
	

}
