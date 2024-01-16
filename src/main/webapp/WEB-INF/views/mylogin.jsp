<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>Insert title here</title>
	</head>
	<body>
		<h1>mylogin.jsp</h1>
		<!-- action, method 속성 고정 -->
		<form action="/login" method="post">
			아이디 : <input type="text" name="username"><br>
			비밀번호 : <input type="password" name="password"><br>
			<input type="submit" value="로그인">
			<!-- POST 방식 전송시 csrf 토큰 정보가 필요 -->
			<input type="hidden" name="${_csrf.parameterName }" value="${_csrf.token }">
		</form>
	</body>
</html>