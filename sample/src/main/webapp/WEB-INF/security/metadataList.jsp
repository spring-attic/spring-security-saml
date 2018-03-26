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
                        <div class="post-title"><h2 class="label label-green">Metadata administration</h2></div>
                        <p class="quiet large">Overview of all configured metadata for local service providers and remote identity providers.</p>
                        <div class="post-body">
                            <p>
                                <strong>Default local service provider:</strong><br>
                                <c:forEach var="entity" items="${hostedSP}">
                                    <a href="<c:url value="/saml/web/metadata/display"><c:param name="entityId" value="${hostedSP}"/></c:url>">
                                    <c:out value="${hostedSP}"/></a>
                                </c:forEach>
                                <c:if test="${empty hostedSP}"> - </c:if>
                                <br/>
                                <small><i>Default service provider is available without selection of alias.</i></small>
                            </p>
                            <p>
                                <strong>Service providers:</strong><br/>
                                <c:forEach var="entity" items="${spList}">
                                    <a href="<c:url value="/saml/web/metadata/display"><c:param name="entityId" value="${entity}"/></c:url>">
                                        <c:out value="${entity}"/></a><br/>
                                </c:forEach>
                                <c:if test="${empty spList}"> - </c:if>
                            </p>
                            <p>
                                <strong>Identity providers:</strong><br/>
                                <c:forEach var="entity" items="${idpList}">
                                    <a href="<c:url value="/saml/web/metadata/display"><c:param name="entityId" value="${entity}"/></c:url>">
                                        <c:out value="${entity}"/></a><br/>
                                </c:forEach>
                                <c:if test="${empty idpList}"> - </c:if>
                            </p>
                            <p>
                                <strong>Metadata providers:</strong><br/>
                                <c:forEach var="entity" items="${metadata}" varStatus="status">
                                    <a href="<c:url value="/saml/web/metadata/provider"><c:param name="providerIndex" value="${status.index}"/></c:url>">
                                        <c:out value="${entity}"/></a><br/>
                                </c:forEach>
                                <c:if test="${empty metadata}"> - </c:if>
                            </p>
                            <div>
                            <form class="left" action="<c:url value="/saml/web/metadata/generate"/>" method="get">
                                <input type="submit" value="Generate new service provider metadata" class="button"/>
                            </form>
                            <form class="left" action="<c:url value="/saml/web/metadata/refresh"/>">
                                <input type="submit" value="Refresh metadata" class="button"/>
                            </form>
                            </div>
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