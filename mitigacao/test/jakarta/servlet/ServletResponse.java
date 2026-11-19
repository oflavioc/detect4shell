package jakarta.servlet;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * STUB mínimo de {@code jakarta.servlet.ServletResponse} — só {@code setContentType}/{@code getWriter},
 * usados pelo filtro ao responder 400. Harness auto-contido — ver ServletException.java.
 */
public interface ServletResponse {
    void setContentType(String type);
    PrintWriter getWriter() throws IOException;
}
