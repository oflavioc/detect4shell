package jakarta.servlet;

/**
 * STUB mínimo de {@code jakarta.servlet.ServletException} — só o suficiente para o harness
 * auto-contido ({@code mitigacao/test/}) compilar e rodar o {@link detect4shell.Java4ShellFilter}
 * sem baixar a servlet-api. NÃO é a API real: só a superfície que o filtro usa. Assinatura
 * idêntica em jakarta.servlet 6.0 e javax.servlet 4.0.1.
 */
public class ServletException extends Exception {
    public ServletException() { super(); }
    public ServletException(String message) { super(message); }
}
