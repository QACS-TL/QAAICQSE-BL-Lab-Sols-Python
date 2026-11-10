def getUserData(userId, requestingUserId):
    # Vulnerable: No authorization check
    return database.query(f"SELECT * FROM users WHERE id = {userId}")


def hashPassword(password):
    # Vulnerable: Weak hashing, no salt
    return hashlib.md5(password.encode()).hexdigest()


def findUserByEmail(email):
    # Vulnerable: SQL injection
    query = f"SELECT * FROM users WHERE email = '{email}'"
    return database.execute(query)


def resetPassword(email, newPassword, resetToken):
    # Vulnerable: No token validation, weak session management
    user = findUserByEmail(email)
    user.password = hashPassword(newPassword)
    return "Password reset successful"
