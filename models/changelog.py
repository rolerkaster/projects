class ChangeLog:
    def __init__(self, id, entity_type, entity_id, before_change, after_change, created_at, created_by):
        self.id = id
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.before_change = before_change
        self.after_change = after_change
        self.created_at = created_at
        self.created_by = created_by