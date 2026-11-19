package jakarta.servlet;

import java.util.Map;

/**
 * STUB mínimo de {@code jakarta.servlet.ServletRequest} — só os métodos que o filtro chama no tipo
 * base ({@code getServletContext}/{@code getRemoteAddr}) e os herdados usados via HttpServletRequest
 * ({@code getParameterMap}/{@code getContentType}). Assinaturas idênticas às da API real (jakarta 6.0
 * / javax 4.0.1). Harness auto-contido — ver ServletException.java.
 */
public interface ServletRequest {
    Map<String, String[]> getParameterMap();
    String getContentType();
    String getRemoteAddr();
    ServletContext getServletContext();
}
