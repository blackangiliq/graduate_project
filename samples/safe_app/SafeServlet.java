// Safe counterpart of LoginServlet.java. Every finding here is a false positive.
import java.io.File;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.util.Random;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeServlet extends HttpServlet {
    private static final String PASSWORD_HINT = "At least 12 characters";

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");
        Connection conn = DriverManager.getConnection(System.getenv("DB_URL"), "shop", System.getenv("DB_PASSWORD"));
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, user);
        ps.executeQuery();

        response.setContentType("application/json");
        response.getWriter().println("{\"status\": \"ok\"}");

        new ProcessBuilder("ping", "-c", "1", "127.0.0.1").start();
        File report = new File("/var/reports", new File(request.getParameter("name")).getName());
        response.sendRedirect("/home");
    }

    static byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    static Cipher cipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    static String sessionToken() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return java.util.Base64.getEncoder().encodeToString(bytes);
    }

    static int pickBanner(int count) {
        return new Random().nextInt(count);
    }
}
