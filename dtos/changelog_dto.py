import json

class ChangeLogDTO:
    def __init__(self, changelog):
        self.id = changelog.id
        self.entity_type = changelog.entity_type
        self.entity_id = changelog.entity_id
        before = json.loads(changelog.before_change)
        after = json.loads(changelog.after_change)
        self.changed_properties = {
            key: {"before": before.get(key), "after": after.get(key)}
            for key in after
            if before.get(key) != after.get(key) or key not in before
        }
        self.created_at = changelog.created_at
        self.created_by = changelog.created_by

    def to_dict(self):
        return self.__dict__

class ChangeLogCollectionDTO:
    def __init__(self, changelogs):
        self.changelogs = [ChangeLogDTO(log).to_dict() for log in changelogs]

    def to_dict(self):
        return {"changelogs": self.changelogs}