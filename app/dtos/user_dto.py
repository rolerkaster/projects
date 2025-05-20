from .role_dto import RoleDTO

class UserDTO:
    def __init__(self, user):
        self.username = user.username
        self.email = user.email
        self.birthday = user.birthday
        self.roles = [RoleDTO(role).to_dict() for role in user.roles()]
        self.two_factor_enabled = bool(getattr(user, 'two_factor_enabled', 0))

    def to_dict(self):
        return self.__dict__