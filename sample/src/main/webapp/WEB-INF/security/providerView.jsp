<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
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
                        <div class="post-title"><h2 class="label label-green">Metadata provider detail</h2></div>
                        <p class="quiet large">Overview of a metadata provider which can include multiple SAML entities.</p>
                        <div class="post-body">
                            <p><a href="<c:url value="/saml/web/metadata"/>">&lt;&lt Back</a></p>
                            <strong>Provider:</strong> <c:out value="${provider}"/>
                            <p>
                            <form:form commandName="provider" action="removeProvider">
                                <input type="hidden" name="providerIndex" value="<c:out value="${providerIndex}"/>"/>
                                <input type="submit" class="button" value="Remove provider"/>
                            </form:form>
                            <br>
                            <p><a href="<c:url value="/saml/web/metadata"/>">&lt;&lt Back</a></p>
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