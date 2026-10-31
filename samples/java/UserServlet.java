import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;

/** Servlet used as a vulnerable test fixture (issues are labelled with EXPECT). */
public class UserServlet extends HttpServlet {
    private static final String DB_URL = "jdbc:mysql://localhost/app";
    private static final String DB_PASSWORD = "Sup3rSecret!";  // EXPECT: HARDCODED_SECRET

    /** Look a user up. */
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        try {
            Connection conn = DriverManager.getConnection(DB_URL, "app", DB_PASSWORD);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");  // EXPECT: SQL_INJECTION
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println("<p>User: " + rs.getString("name") + "</p>");  // EXPECT: XSS
            }
            out.println("<h2>Results for " + name + "</h2>");  // EXPECT: XSS
        } catch (Exception e) {  // EXPECT: BROAD_EXCEPT
            e.printStackTrace();
        }
    }

    /** Send a stored document. */
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String file = request.getParameter("file");
        File doc = new File("/var/docs/" + file);  // EXPECT: PATH_TRAVERSAL
        FileInputStream in = new FileInputStream(doc);
        in.transferTo(response.getOutputStream());
        in.close();
    }

    /** Redirect the visitor. */
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String next = request.getParameter("next");
        response.sendRedirect(next);  // EXPECT: OPEN_REDIRECT
    }

    /** Run a diagnostic command. */
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String host = request.getParameter("host");
        Runtime.getRuntime().exec("ping -c 1 " + host);  // EXPECT: COMMAND_INJECTION
    }

    /** Hash a password. */
    static byte[] hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");  // EXPECT: WEAK_CRYPTO
        return md.digest(password.getBytes());
    }

    /** Parse an uploaded XML document. */
    static void parse(java.io.InputStream data) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();  // EXPECT: XXE
        factory.newDocumentBuilder().parse(data);
    }

    /** Create the session cookie. */
    static Cookie sessionCookie(String id) {
        Cookie cookie = new Cookie("SESSIONID", id);
        cookie.setHttpOnly(false);  // EXPECT: INSECURE_COOKIE
        return cookie;
    }
}
