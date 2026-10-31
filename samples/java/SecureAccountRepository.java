import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/** Repository written to follow the secure coding rules (no findings expected). */
public class SecureAccountRepository {
    private static final int TOKEN_BYTES = 32;
    private final Connection connection;
    private final SecureRandom random = new SecureRandom();

    /**
     * Creates the repository.
     *
     * @param connection an open database connection
     */
    public SecureAccountRepository(Connection connection) {
        this.connection = connection;
    }

    /**
     * Finds the names of accounts with the given login.
     *
     * @param login the login to look for
     * @return the matching names
     * @throws SQLException if the query fails
     */
    public List<String> findNames(String login) throws SQLException {
        List<String> names = new ArrayList<>();
        try (PreparedStatement stmt = connection.prepareStatement("SELECT name FROM accounts WHERE login = ?")) {
            stmt.setString(1, login);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    names.add(rs.getString("name"));
                }
            }
        }
        return names;
    }

    /**
     * Creates an unpredictable reset token.
     *
     * @return a URL-safe token
     */
    public String newResetToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Hashes a value with SHA-256.
     *
     * @param value the text to hash
     * @return the digest
     * @throws Exception if SHA-256 is unavailable
     */
    public byte[] digest(String value) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Reads the database password from the environment.
     *
     * @return the password or null
     */
    public static String dbPassword() {
        return System.getenv("DB_PASSWORD");
    }
}
