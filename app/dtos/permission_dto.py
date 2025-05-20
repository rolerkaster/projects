class PermissionDTO:
    def __init__(self, perm):
        self.id = perm.id
        self.name = perm.name
        self.description = perm.description
        self.code = perm.code

    def to_dict(self):
        return self.__dict__

class PermissionCollectionDTO:
    def __init__(self, perms):
        self.permissions = [PermissionDTO(perm).to_dict() for perm in perms]

    def to_dict(self):
        return {"permissions": self.permissions}