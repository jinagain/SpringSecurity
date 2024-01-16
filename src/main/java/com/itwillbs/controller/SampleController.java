package com.itwillbs.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * 
 * Spring Web Security : 필터와 인터셉터를 사용해서 다양한 정보를 처리하도록 수행하는 작업
 * 							보안적 요소를 구현하기 위해서 사용(인증, 허가)
 * 
 * 필터 : 서블릿 기반의 동작, 데이터를 원하는 형태로 받거나, 출력해서 사용가능
 * 인터셉터 : 스프링기반의 동작, 스프링의 자원 활용하여, 데이터를 제어
 * 
 * spring security web
 * spring security config
 * spring security core
 * => 위 3개의 라이브러리 버전은 동일해야 함
 * 
 * spring security taglibs
 * 
 * 인증(Authentication) : 자신을 증명하는 작업 (출입증, 신분증)
 * 
 * 인가(Authorization) : 남에 의해서 자격이 부여되는 작업 (출입증(+권한))
 * (권한을 부여)
 * 
 * 사용자의 아이디(userid/id = (시큐리티) => username
 * * 사용자의 이름 username 시큐리티 적용코드에서 사용X
 * 
 * 사용자 (member/user = (시큐리티) => user)
 * * 인증정보 + 권한을 가진 사용자 User
 *
 */

@Controller
public class SampleController {
	
	private static final Logger logger = LoggerFactory.getLogger(SampleController.class);
	
	// 모든 유저(비로그인) 접근 가능 페이지
	@RequestMapping(value = "/all", method = RequestMethod.GET)
	public void doAll() {
		logger.debug(" doAll() 호출 - 모든 사용자 접근가능 ");
	}
	
	// 회원만(로그인) 접근가능 페이지
	@RequestMapping(value = "/member", method = RequestMethod.GET)
	public void doMember() {
		logger.debug(" doMember() 호출 - 회원만 접근가능 ");
	}
	// 관리자만 접근가능 페이지
	@RequestMapping(value = "/admin", method = RequestMethod.GET)
	public void doAdmin() {
		logger.debug(" doAdmin() 호출 - 관리자만 접근가능 ");
	}

}
