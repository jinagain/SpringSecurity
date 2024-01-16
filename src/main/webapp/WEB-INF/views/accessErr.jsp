<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>Insert title here</title>
	</head>
	<body>
		<h1>accessErr.jsp</h1>
		<h2>페이지 접근 권한이 없음</h2>
		<h3>원래 페이지로 돌아가세요!</h3>
		<%
			response.addHeader("Refresh", "5 url=/all");
		%>
		<a href="/all"> 홈으로</a>
		
		<hr>
		
		${auth }
		
		<hr>
		
		${SPRING_SECURITY_403_EXCEPTION.getMessage() }
	</body>
</html>