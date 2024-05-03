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
