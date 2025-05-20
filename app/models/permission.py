class Permission:
    def __init__(self, id, name, description, code, created_at, created_by, deleted_at=None, deleted_by=None):
        self.id = id
        self.name = name
        self.description = description
        self.code = code
        self.created_at = created_at
        self.created_by = created_by
        self.deleted_at = deleted_at
        self.deleted_by = deleted_by