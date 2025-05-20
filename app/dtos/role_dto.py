from .permission_dto import PermissionDTO

class RoleDTO:
    def __init__(self, role):
        self.id = role.id
        self.name = role.name
        self.description = role.description
        self.code = role.code
        self.permissions = [PermissionDTO(perm).to_dict() for perm in role.permissions()]

    def to_dict(self):
        return self.__dict__

class RoleCollectionDTO:
    def __init__(self, roles):
        self.roles = [RoleDTO(role).to_dict() for role in roles]

    def to_dict(self):
        return {"roles": self.roles}