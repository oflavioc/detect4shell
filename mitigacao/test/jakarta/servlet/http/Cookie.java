package jakarta.servlet.http;

/**
 * STUB mínimo de {@code jakarta.servlet.http.Cookie} — só o construtor {@code (nome, valor)} e os
 * getters que o filtro usa ({@code getName}/{@code getValue}). Ver ServletException.java.
 */
public class Cookie {
    private final String name;
    private final String value;

    public Cookie(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public String getName() { return name; }

    public String getValue() { return value; }
}
