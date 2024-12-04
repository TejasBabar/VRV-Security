package Role.Based.Access.Security.RBAS.Using.Spring.Security;

import java.util.*;

public class RoleBasedAccessControl {
    enum Role {
        ADMIN, USER, PUBLIC
    }

    static class User {
        String username;
        String password;
        Role role;

        User(String username, String password, Role role) {
            this.username = username;
            this.password = password;
            this.role = role;
        }
    }

    static class AuthSystem {
        private final Map<String, User> users = new HashMap<>();
        User loggedInUser = null;

        // Register a new user
        public void register(String username, String password, Role role) {
            if (users.containsKey(username)) {
                System.out.println("Username already exists. Please choose a different username.");
                return;
            }
            users.put(username, new User(username, password, role));
            System.out.println("User registered successfully!");
        }

        // Login a user
        public void login(String username, String password) {
            if (loggedInUser != null) {
                System.out.println("A user is already logged in. Logout first.");
                return;
            }

            User user = users.get(username);
            if (user == null || !user.password.equals(password)) {
                System.out.println("Invalid username or password.");
                return;
            }

            loggedInUser = user;
            System.out.println("Welcome, " + loggedInUser.username + "!");
        }

        // Logout the currently logged-in user
        public void logout() {
            if (loggedInUser == null) {
                System.out.println("No user is currently logged in.");
                return;
            }

            System.out.println("Goodbye, " + loggedInUser.username + "!");
            loggedInUser = null;
        }

        // Access specific pages based on the user's role
        public void accessPage(String page) {
            if (loggedInUser == null) {
                System.out.println("Please log in to access the page.");
                return;
            }

            switch (page.toLowerCase()) {
                case "admin":
                    if (loggedInUser.role == Role.ADMIN) {
                        System.out.println("Welcome to the admin page!");
                    } else {
                        System.out.println("Access denied. Admins only.");
                    }
                    break;
                case "user":
                    if (loggedInUser.role == Role.USER || loggedInUser.role == Role.ADMIN) {
                        System.out.println("Welcome to the user page!");
                    } else {
                        System.out.println("Access denied. Users only.");
                    }
                    break;
                case "public":
                    System.out.println("Welcome to the public page!");
                    break;
                default:
                    System.out.println("Page not found.");
            }
        }
    }

    public static void main(String[] args) {
        AuthSystem authSystem = new AuthSystem();
        Scanner scanner = new Scanner(System.in);

        authSystem.register("admin", "admin123", Role.ADMIN);
        authSystem.register("user1", "user123", Role.USER);

        while (true) {
            System.out.println("\nOptions: register, login, logout, access, exit");
            System.out.print("Enter your choice: ");
            String choice = scanner.next();

            switch (choice.toLowerCase()) {
                case "register":
                    System.out.print("Enter username: ");
                    String username = scanner.next();
                    System.out.print("Enter password: ");
                    String password = scanner.next();
                    System.out.print("Enter role (ADMIN/USER): ");
                    String roleStr = scanner.next();
                    Role role;
                    try {
                        role = Role.valueOf(roleStr.toUpperCase());
                    } catch (IllegalArgumentException e) {
                        System.out.println("Invalid role. Please use ADMIN or USER.");
                        break;
                    }
                    authSystem.register(username, password, role);
                    break;
                case "login":
                    System.out.print("Enter username: ");
                    username = scanner.next();
                    System.out.print("Enter password: ");
                    password = scanner.next();
                    authSystem.login(username, password);
                    break;
                case "logout":
                    authSystem.logout();
                    break;
                case "access":
                    System.out.print("Enter page (admin/user/public): ");
                    String page = scanner.next();
                    authSystem.accessPage(page);
                    break;
                case "exit":
                    System.out.println("Exiting the system. Goodbye!");
                    scanner.close();
                    return;
                default:
                    System.out.println("Invalid option. Please try again.");
            }
        }
    }
}
