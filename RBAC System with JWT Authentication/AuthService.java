import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class AuthService {
    private static final String SECRET_KEY = "SECRET123";
    private Map<String, User> users = new HashMap<>();
    private Map<String, List<String>> rolePermissions = new HashMap<>();

    public AuthService() {
        // Initialize roles and permissions
        rolePermissions.put("ADMIN", Arrays.asList("VIEW", "EDIT", "DELETE", "MANAGE_USERS"));
        rolePermissions.put("USER", Collections.singletonList("VIEW"));

        // Add default users
        users.put("admin", new User("admin", hashPassword("admin123"), "ADMIN"));
        users.put("user", new User("user", hashPassword("user123"), "USER"));
    }

    // Authenticate a user with username and password
    public String authenticate(String username, String password) {
        User user = users.get(username);
        if (user != null && user.getHashedPassword().equals(hashPassword(password))) {
            return generateJwtToken(user);
        }
        return null;
    }

    // Generate JWT token for authenticated user
    private String generateJwtToken(User user) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
        return JWT.create()
                .withSubject(user.getUsername())
                .withClaim("role", user.getRole())
                .withIssuedAt(new Date())
                .sign(algorithm);
    }

    // Validate JWT token
    public DecodedJWT validateJwtToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
            JWTVerifier verifier = JWT.require(algorithm)
                    .build();
            return verifier.verify(token);
        } catch (JWTVerificationException exception) {
            return null; // Invalid token
        }
    }

    // Authorize action based on role and action
    public boolean authorize(String role, String action) {
        return rolePermissions.getOrDefault(role, Collections.emptyList()).contains(action);
    }

    // Hash password with SHA-256
    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] salt = "RANDOM_SALT".getBytes(); // Salt for password hashing
            md.update(salt);
            byte[] hashBytes = md.digest(password.getBytes());
            StringBuilder hashString = new StringBuilder();
            for (byte b : hashBytes) {
                hashString.append(String.format("%02x", b));
            }
            return hashString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }
}
