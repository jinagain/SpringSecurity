package com.itwillbs.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/***
 * 
 * 프로젝트에서 발생하는 공통의 동작을 수행하는 객체
 * 
 *
 */
@Controller
public class CommonController {

	private static final Logger logger = LoggerFactory.getLogger(CommonController.class);
	
	// http://localhost:8088/accessErr
	// 페이지 접근권한이 없을 때 처리 페이지
	@RequestMapping(value = "/accessErr", method = RequestMethod.GET)
	public void accessDenied(Authentication auth, Model model) throws Exception{
		logger.debug(" accessDenied() 호출 ");
		logger.debug(" 접근권한없는 사용자가 접근! ");
		
		model.addAttribute("auth", auth);
		
	}
	
	// 로그인 페이지
	@RequestMapping(value = "/mylogin", method = RequestMethod.GET)
	public void myLogin() throws Exception {
		logger.debug("myLogin() 호출");
	}
	
	// 로그아웃 페이지
	@RequestMapping(value = "/mylogout", method = RequestMethod.GET)
	public void mylogout() throws Exception {
		
		logger.debug("mylogout() 호출");
	}
}
