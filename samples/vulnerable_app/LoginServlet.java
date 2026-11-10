// Deliberately vulnerable servlet. FOR TESTING THE ANALYZER ONLY.
import java.io.File;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet extends HttpServlet {
    private static final String DB_PASSWORD = "Adm1n#Passw0rd"; // [A01]

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/shop", "root", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'"); // [A02]

        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?"); // [A03]
        ps.setString(1, user);

        response.getWriter().println("<p>Hello " + user + "</p>"); // [A04]
        Runtime.getRuntime().exec("ping -c 1 " + request.getParameter("host")); // [A05]
        File report = new File("/var/reports/" + request.getParameter("name")); // [A06]
        response.sendRedirect(request.getParameter("next")); // [A07]
    }

    static String hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // [A08]
        return new String(md.digest(password.getBytes()));
    }

    static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding"); // [A09]
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    static String sessionToken() {
        String token = Long.toHexString(new Random().nextLong()); // [A10]
        return token;
    }

    static Object load(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in); // [A11]
        return ois.readObject();
    }

    static byte[] strongHash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256"); // [A12]
        return md.digest(data);
    }

    static String secureToken() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes); // [A13]
        return java.util.Base64.getEncoder().encodeToString(bytes);
    }
}
