from django.db import models
from . import permpp

def PermissionsMixin_factory(group_roles, user_perms) -> type:
    class PermissionsMixin:
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            setattr(self, "can", f"A dummy value {group_roles} {user_perms}")

        @property
        def cached_groups(self):
              print('cached_group things')

    return PermissionsMixin

PermissionsMixin = PermissionsMixin_factory("foo", "bar")

class Groups(models.TextChoices):
    ADMIN = "Leasing Admin"
    AGENT = "Leasing Agent"


GroupDescriptions = {
    Groups.ADMIN: "Perform Leasing activities, in particular scoring leases",
    Groups.AGENT: "Perform Leasing activities, in particular sending out leas applications and agent reviewing them",
}



gps = permpp.GroupPerms()
gps.add(
    'admin',
    "Admin Access",
)

grs = permpp.GroupRoles(gps)
grs.add_group(GroupDescriptions, Groups.ADMIN, gps.admin)
ups = permpp.UserPerms()
PermissionsMixin = permpp.PermissionsMixin_factory(grs, ups)
