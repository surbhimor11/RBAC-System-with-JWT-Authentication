# RBAC-System-with-JWT-Authentication

This is a simple **Role-Based Access Control (RBAC)** system implemented in Java that integrates **JWT authentication** for secure session management. It allows users to log in, access resources based on their role, and perform actions such as `VIEW`, `EDIT`, and `DELETE`.

---

## **Features**

1. **JWT Authentication**:
   - Users can log in with a username and password.
   - On successful authentication, users receive a JWT token that is used for subsequent requests.
   
2. **Role-Based Access Control**:
   - `ADMIN`: Can perform all actions (VIEW, EDIT, DELETE, MANAGE_USERS).
   - `USER`: Can only perform the `VIEW` action.
   - Roles are assigned to users, and actions are authorized based on roles.

3. **Session Management**:
   - JWT is used for managing user sessions in a stateless manner.
   - The token stores user role information and is validated for each request.

4. **Security**:
   - Passwords are securely stored using SHA-256 hashing with salt.
   - JWTs are signed with a secret key for integrity and security.

---

## **Prerequisites**
- Java Development Kit (JDK) 8 or higher
- Maven or Gradle for dependency management 
