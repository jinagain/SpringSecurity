package com.itwillbs.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.jaas.AuthorityGranter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/*
 * 로그인 성공 시 처리 동작
 */
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler{
	
	private static final Logger logger = LoggerFactory.getLogger(CustomLoginSuccessHandler.class);

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		// 인증 성공시 처리 동작
		logger.debug(" onAuthenticationSuccess() 호출 ");
		
		// 로그인 유저의 권한에 따른 페이지 이동
		// 기존의 권한정보 확인
		logger.debug("auth : " + authentication);
		List<String> roleNames = new ArrayList<String>();
		
		authentication.getAuthorities().forEach(autgority -> roleNames.add(autgority.getAuthority()));
		
//		authentication.getAuthorities().forEach(new Consumer<GrantedAuthority>() {
//			@Override
//			public void accept(GrantedAuthority authgority) {
//				roleNames.add(authgority.getAuthority());				
//			}			
//		});
		
		// ROLE_MEMBER -> /member 페이지 이동
		if(roleNames.contains("ROLE_MEMBER")) {
			// ex) 추가적인 동작(세션에 정보 저장하기...)
//			HttpSession session = request.getSession();
//			session.setAttribute(name, value);
			response.sendRedirect("/member");
			return;
		}
		// ROLE_ADMIN -> /admin 페이지 이동
		if(roleNames.contains("ROLE_ADMIN")) {
			response.sendRedirect("/admin");
			return;
		}
		
		response.sendRedirect("/all");
	}
}
