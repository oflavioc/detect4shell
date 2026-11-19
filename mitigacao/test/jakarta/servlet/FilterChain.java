package jakarta.servlet;

import java.io.IOException;

/**
 * STUB mínimo de {@code jakarta.servlet.FilterChain} — só {@code doFilter(req, resp)}. O harness usa
 * um fake que marca se a cadeia foi chamada (= requisição deixada passar). Ver ServletException.java.
 */
public interface FilterChain {
    void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException;
}
