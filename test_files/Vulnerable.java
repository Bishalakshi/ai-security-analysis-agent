import java.sql.*;
import java.security.MessageDigest;

public class Vulnerable {
    private String password = "admin123";

    public ResultSet find(Connection c, String name) throws Exception {
        Statement st = c.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public byte[] hash(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(s.getBytes());
    }

    public void run(String cmd) {
        try {
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
