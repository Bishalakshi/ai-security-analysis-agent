import java.io.ObjectInputStream;
import java.io.InputStream;
import java.util.Random;
import javax.net.ssl.HostnameVerifier;  // EXPECT: UNUSED_IMPORT
import javax.net.ssl.HttpsURLConnection;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.jdbc.core.JdbcTemplate;

/** Spring controller used as a vulnerable test fixture. */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")  // EXPECT: PERMISSIVE_CORS
public class AdminController {
    private final JdbcTemplate jdbc;

    public AdminController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Delete any account. */
    @DeleteMapping("/admin/users/{id}")  // EXPECT: BROKEN_ACCESS_CONTROL
    public void deleteUser(@PathVariable long id) {
        jdbc.update("DELETE FROM users WHERE id = ?", id);
    }

    /** Look up an account by login. */
    @GetMapping("/accounts")
    public Object byLogin(@RequestParam String login) {
        return jdbc.queryForList("SELECT * FROM accounts WHERE login = '" + login + "'");  // EXPECT: SQL_INJECTION
    }

    /** Import a serialized object. */
    @PostMapping("/import")
    public Object importData(InputStream body) throws Exception {
        ObjectInputStream in = new ObjectInputStream(body);  // EXPECT: INSECURE_DESERIALIZATION
        return in.readObject();
    }

    /** Create a password reset token. */
    public String resetToken() {
        Random random = new Random();  // EXPECT: INSECURE_RANDOM
        return Long.toHexString(random.nextLong());
    }

    /** Accept every certificate. */
    public void trustEverything(HttpsURLConnection connection) {
        connection.setHostnameVerifier((host, session) -> true);  // EXPECT: TLS_VERIFY_DISABLED
    }

    /** Plain text comparison of passwords. */
    public boolean login(String stored, String password) {
        return stored.equals(password);  // EXPECT: INSECURE_AUTH
    }

    /** Write the credential to the log. */
    public void audit(String user, String password) {
        System.out.println("login " + user + " password=" + password);  // EXPECT: SENSITIVE_LOGGING
    }
}
