package com.example.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Random;

@RestController
public class VulnerableController {

    // 1. Hardcoded Credentials (Vulnerability / Hotspot)
    private static final String DEFAULT_PASSWORD = "super_secret_admin_password!";
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    private static final String DB_USER = "root";
    private static final String DB_PASS = "root123"; // Sonar scanner will flag this strongly

    // 2. SQL Injection (Vulnerability)
    @GetMapping("/api/user")
    public String getUserInfo(@RequestParam("username") String username) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
            Statement stmt = conn.createStatement();
            
            // The following line is highly vulnerable to SQL injection
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            stmt.executeQuery(query);
            
            // 3. Reflected XSS (Vulnerability)
            return "Query executed for user: " + username; 
        } catch (Exception e) {
            // 4. Information Exposure (Hotspot)
            e.printStackTrace(); 
            return "Error";
        }
    }

    // 5. OS Command Injection (Vulnerability)
    @GetMapping("/api/ping")
    public String pingServer(@RequestParam("ip") String ip) {
        StringBuilder output = new StringBuilder();
        try {
            // Very dangerous! Allows execution of arbitrary OS commands
            Process process = Runtime.getRuntime().exec("ping -c 1 " + ip);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return output.toString();
    }

    // 6. Weak Cryptography (Vulnerability / Hotspot)
    @GetMapping("/api/hash")
    public String hashPassword(@RequestParam("password") String password) {
        try {
            // MD5 is broken and should not be used for security (Sonar flags this)
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(password.getBytes());
            return new String(digest);
        } catch (Exception e) {
            return "Error";
        }
    }

    // 7. Predictable Random / Weak PRNG (Hotspot)
    @GetMapping("/api/token")
    public String generateToken() {
        // java.util.Random is not cryptographically secure
        Random rand = new Random(); 
        int token = rand.nextInt(1000000);
        return "Generated token: " + token;
    }
}
