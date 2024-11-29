import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Scanner;

public class RbacApp {
    public static void main(String[] args) {
        AuthService authService = new AuthService();
        Scanner scanner = new Scanner(System.in);

        System.out.println("Welcome to the Enhanced RBAC System with JWT!");

        // Login
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        String token = authService.authenticate(username, password);
        if (token == null) {
            System.out.println("Authentication failed. Exiting...");
            return;
        }

        // Token validated
        System.out.println("Login successful! Your token: " + token);

        // Validate token and authorize actions
        DecodedJWT decodedJWT = authService.validateJwtToken(token);
        if (decodedJWT == null) {
            System.out.println("Invalid token. Exiting...");
            return;
        }

        String role = decodedJWT.getClaim("role").asString();
        System.out.println("Your role is: " + role);

        while (true) {
            System.out.println("\nAvailable actions: VIEW, EDIT, DELETE, MANAGE_USERS, EXIT");
            System.out.print("Enter action: ");
            String action = scanner.nextLine().toUpperCase();

            if (action.equals("EXIT")) {
                System.out.println("Goodbye!");
                break;
            }

            if (authService.authorize(role, action)) {
                if (action.equals("MANAGE_USERS") && role.equals("ADMIN")) {
                    System.out.print("Enter username to register: ");
                    String newUser = scanner.nextLine();
                    System.out.print("Enter password: ");
                    String newPassword = scanner.nextLine();
                    // For simplicity, user registration is simulated here.
                    System.out.println("User registered successfully!");
                } else {
                    System.out.println("Action '" + action + "' performed successfully!");
                }
            } else {
                System.out.println("You are not authorized to perform this action.");
            }
        }
        scanner.close();
    }
}
