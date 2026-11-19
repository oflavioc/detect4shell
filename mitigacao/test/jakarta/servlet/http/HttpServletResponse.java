package jakarta.servlet.http;

import jakarta.servlet.ServletResponse;

/**
 * STUB mínimo de {@code jakarta.servlet.http.HttpServletResponse} — só {@code setStatus(int)} e a
 * constante {@code SC_BAD_REQUEST} (400), usados pelo filtro ao negar. Ver ServletException.java.
 */
public interface HttpServletResponse extends ServletResponse {
    int SC_BAD_REQUEST = 400;

    void setStatus(int sc);
}
