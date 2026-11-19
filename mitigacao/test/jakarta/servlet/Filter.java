package jakarta.servlet;

import java.io.IOException;

/**
 * STUB mínimo de {@code jakarta.servlet.Filter} — a interface que o {@link detect4shell.Java4ShellFilter}
 * implementa. {@code init} e {@code destroy} são {@code default} (como na API real), então o filtro só
 * precisa prover {@code doFilter}. Assinaturas idênticas às de jakarta 6.0 / javax 4.0.1.
 * Harness auto-contido — ver ServletException.java.
 */
public interface Filter {
    default void init(FilterConfig filterConfig) throws ServletException { }

    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException;

    default void destroy() { }
}
