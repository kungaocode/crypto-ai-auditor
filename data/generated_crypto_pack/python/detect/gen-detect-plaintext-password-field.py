def register_user(db, email: str, password: str):
    user = db.User(email=email)
    user.password = password
    db.add(user)
    db.commit()
    return user
