package jakarta.servlet;

/**
 * STUB mínimo de {@code jakarta.servlet.FilterConfig} — só {@code getInitParameter(String)}, que o
 * filtro lê em {@code init()} para {@code mode}/{@code skipFormBody}. Ver ServletException.java.
 */
public interface FilterConfig {
    String getInitParameter(String name);
}
