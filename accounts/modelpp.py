from typing import Protocol


class UserNameProtocol(Protocol):
    first_name: str
    last_name: str

def clean_name(s: str):
    return s.title().strip()

class NiceNameMixin:
    @property
    def nice_first_name(self: UserNameProtocol):
        return clean_name(self.first_name)

    @property
    def nice_last_name(self: UserNameProtocol):
        return clean_name(self.last_name)

    @property
    def nice_full_name(self: UserNameProtocol):
        return clean_name(self.first_name + ' ' + self.last_name)
