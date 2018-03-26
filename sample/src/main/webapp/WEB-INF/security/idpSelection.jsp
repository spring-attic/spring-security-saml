<%@ page import="org.springframework.security.saml.metadata.MetadataManager" %>
<%@ page import="org.springframework.web.context.WebApplicationContext" %>
<%@ page import="org.springframework.web.context.support.WebApplicationContextUtils" %>
<%@ page import="java.util.Set" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" dir="ltr">
<jsp:include page="/WEB-INF/templates/head.jsp" />
<body>
<div id="site-wrapper">
<jsp:include page="/WEB-INF/templates/navigation.jsp" />
<div class="main" id="main-two-columns">
    <div class="left" id="main-content">
        <div class="section">
            <div class="section-content">
                <div class="post">
                    <div class="post-title"><h2 class="label label-green">IDP Selection</h2></div>
                    <p class="quiet large">Please select Identity Provider to authenticate with.</p>
                    <div class="post-body">
                        <%
                            WebApplicationContext context = WebApplicationContextUtils.getWebApplicationContext(getServletConfig().getServletContext());
                            MetadataManager mm = context.getBean("metadata", MetadataManager.class);
                            Set<String> idps = mm.getIDPEntityNames();
                            pageContext.setAttribute("idp", idps);
                        %>
                        <p>
                        <form action="<c:url value="${requestScope.idpDiscoReturnURL}"/>" method="GET">
                            <c:forEach var="idpItem" items="${idp}">
                                <input type="radio" name="${requestScope.idpDiscoReturnParam}" id="idp_<c:out value="${idpItem}"/>" value="<c:out value="${idpItem}"/>"/>
                                <label for="idp_<c:out value="${idpItem}"/>"><c:out value="${idpItem}"/></label>
                                <br/>
                            </c:forEach>
                            <br>
                            <input class="button" type="submit" value="Start single sign-on"/>
                        </form>
                    </div>
                </div>
                <div class="clearer">&nbsp;</div>
            </div>
        </div>
        <div class="clearer">&nbsp;</div>
    </div>
    <jsp:include page="/WEB-INF/templates/sidebar.jsp" />
</div>
<jsp:include page="/WEB-INF/templates/footer.jsp" />
</div>
</body>
</html>