package com.itwillbs.controller;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration({
	"file:src/main/webapp/WEB-INF/spring/root-context.xml",
	"file:src/main/webapp/WEB-INF/spring/security-context.xml",
})
public class MemberPasswordTest {
	
	// 암호화처리 객체주입
	@Autowired
	private PasswordEncoder passEncoder;
	
	private static final Logger logger = LoggerFactory.getLogger(MemberPasswordTest.class);
	
	@Test
	public void test() throws Exception {
		logger.debug("passEncoder : " + passEncoder);
	}
	@Test
	public void 비밀번호암호화_test() throws Exception {
		String oldPW = "itwill1234";
		logger.info(" 비밀번호(암호화 전) : " + oldPW);
		
		String newPW = passEncoder.encode(oldPW);
		logger.info(" 비밀번호(암호화 후) : " + newPW);
		
		if(passEncoder.matches(oldPW, newPW)) {
			logger.info("비밀번호는 동일!");
		}
	}
}
