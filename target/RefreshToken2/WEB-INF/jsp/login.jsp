<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%--
  Created by IntelliJ IDEA.
  User: Ashish.Modh
  Date: 9/1/2022
  Time: 12:48 PM
  To change this template use File | Settings | File Templates.
--%>
<html>
<head>
    <title>Login Form</title>
</head>
<body>
<h1>Login</h1>
<form name='f' action="/authenticate" method='POST'>
    <table>
        <tr>
            <td>User:</td>
            <td><input type='text' name='username' value=''></td>
        </tr>
        <tr>
            <td>Password:</td>
            <td><input type='password' name='password' /></td>
        </tr>
        <tr>
            <td><input name="submit" type="submit" value="submit" /></td>
        </tr>
    </table>
</form>
</body>
</html>