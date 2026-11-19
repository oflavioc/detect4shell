package jakarta.servlet.http;

import jakarta.servlet.ServletRequest;
import java.util.Enumeration;

/**
 * STUB mínimo de {@code jakarta.servlet.http.HttpServletRequest} — SÓ os métodos que o filtro chama:
 * headers ({@code getHeaderNames}/{@code getHeaders}), query ({@code getQueryString}), método/content-type,
 * cookies e — para a cobertura de PATH (finding #7) — {@code getRequestURI}/{@code getPathInfo}.
 * Assinaturas idênticas às de jakarta 6.0 / javax 4.0.1. Ver ServletException.java.
 */
public interface HttpServletRequest extends ServletRequest {
    Enumeration<String> getHeaderNames();
    Enumeration<String> getHeaders(String name);
    String getQueryString();
    String getMethod();
    String getRequestURI();
    String getPathInfo();
    Cookie[] getCookies();
}
