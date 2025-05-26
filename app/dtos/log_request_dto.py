from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime


@dataclass
class LogRequestShortDTO:
    api_path: str
    controller_path: str
    controller_method: str
    response_status: int
    created_at: str

    @classmethod
    def from_dict(cls, data):
        return cls(
            api_path=data['api_path'],
            controller_path=data['controller_path'],
            controller_method=data['controller_method'],
            response_status=data['response_status'],
            created_at=data['created_at']
        )


@dataclass
class LogRequestDTO:
    id: int
    api_path: str
    http_method: str
    controller_path: str
    controller_method: str
    request_body: Optional[str]
    request_headers: dict
    user_id: Optional[str]
    ip_address: str
    user_agent: str
    response_status: int
    response_body: Optional[str]
    response_headers: dict
    created_at: str

    @classmethod
    def from_dict(cls, data):
        return cls(
            id=data['id'],
            api_path=data['api_path'],
            http_method=data['http_method'],
            controller_path=data['controller_path'],
            controller_method=data['controller_method'],
            request_body=data['request_body'],
            request_headers=data['request_headers'],
            user_id=data['user_id'],
            ip_address=data['ip_address'],
            user_agent=data['user_agent'],
            response_status=data['response_status'],
            response_body=data['response_body'],
            response_headers=data['response_headers'],
            created_at=data['created_at']
        )


@dataclass
class LogRequestCollectionDTO:
    items: List[LogRequestShortDTO]
    total: int
    page: int
    per_page: int
    pages: int

    @classmethod
    def from_dict(cls, data):
        return cls(
            items=[LogRequestShortDTO.from_dict(item) for item in data['items']],
            total=data['total'],
            page=data['page'],
            per_page=data['per_page'],
            pages=data['pages']
        ) 