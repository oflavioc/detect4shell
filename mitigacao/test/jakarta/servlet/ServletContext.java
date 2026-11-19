package jakarta.servlet;

/**
 * STUB mínimo de {@code jakarta.servlet.ServletContext} (só {@code log(String)}, que o filtro usa
 * via {@code req.getServletContext().log(...)}). Harness auto-contido — ver ServletException.java.
 */
public interface ServletContext {
    void log(String msg);
}
