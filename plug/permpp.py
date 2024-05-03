"""
Refer to ./tests/test_permpp for usage

For example if attr_name is 'foo', the permission can be checked on user with:
    user.can.foo
Uses the magic in the classes PermissionGetter and PermissionsMixin below
"""

"""Considered Django-Rules but in templates was very verbose, and seemed quite complicated"""

from collections import namedtuple
from functools import wraps, cache
from typing import Callable, Type

from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import Group as DjangoGroup
from django.core.exceptions import PermissionDenied
from django.utils.decorators import method_decorator
from rest_framework import permissions as drf_permissions

GroupPerm = namedtuple('GroupPerm', 'display_name flag notes enabled')

GETTER_ATTR = "can"


class GroupPerms:
    def __init__(self):
        self.perms = {}
        self.flag_to_enabled = {}
        self.flag_count = 0
        self.add(
            'view_permissions',
            "View permissions",
            notes="View this list of which groups have what permissions",
        )

    def add(
        self, attr_name: str, display_name: str, *, notes: str = "", enabled: bool = True
    ) -> None:
        self.flag_count += 1
        new_flag = 2**self.flag_count
        self.perms[attr_name] = GroupPerm(display_name, new_flag, notes, enabled)
        self.flag_to_enabled[new_flag] = enabled

    def __getattr__(self, name):
        """Used for defining group permission by bitwise ORing flags together"""
        try:
            return self.perms[name].flag
        except AttributeError:
            # Default behaviour
            return self.__getattribute__(name)


# Note: there is no 'key' fields etc, because the key is the name, must match exactly
# If rules is a callable, then it will be passed in the user object and expect a bool return value
GroupRole = namedtuple('GroupRole', 'description flags')


class GroupRoles:
    def __init__(self, group_perms: GroupPerms):
        self.roles: dict[str, GroupRole] = {}
        self.group_perms = group_perms

    def add(self, group_name: str, description: str, flags: int = 0) -> None:
        # Must match the group name in the database `auth_group.name` table exactly
        self.roles[group_name] = GroupRole(description, flags)

    def add_group(self, GroupDescriptions, group, flags: int = 0) -> None:
        self.add(group, GroupDescriptions[group], flags)

    def has_perm(self, attr_name: str, group_names: list[str]) -> bool | None:
        """Return value of None means attr_name was not found"""
        try:
            flag = self.group_perms.perms[attr_name].flag
        except KeyError:
            return None
        for group in group_names:
            role = self.roles.get(group)
            if role:
                enabled = self.group_perms.flag_to_enabled[flag]
                group_has_permission = role.flags & flag
                if enabled and group_has_permission:
                    return True
        else:
            return False

    def get_group_names(self) -> list[str]:
        return list(self.roles.keys())

    def get_group_choices(self):
        return self.get_group_names()

    def get_group_descriptions(self):
        return {k: v.description for k, v in self.roles.items()}


UserPerm = namedtuple('UserPerm', 'func')


class UserPerms:
    def __init__(self):
        self.perms = {}

    def add(self, attr_name: str, func: Callable) -> None:
        self.perms[attr_name] = UserPerm(func)

    def has_perm(self, attr_name: str, user: Type[AbstractUser]) -> bool | None:
        """Return value of None means attr_name was not found"""
        try:
            perm = self.perms[attr_name]
        except KeyError:
            return None
        func = perm.func
        return func(user)


class PermissionGetter:
    """Used by PermissionsMixin to allow one to check for permissions with:
        user.access.foo
    The reason this complicated code is done instead of something like:
        user.access('foo')
    Is that the attributebute look up version works in templates too.
    """

    def __init__(self, user: Type[AbstractUser], group_roles: GroupRoles, user_perms: UserPerms):
        self.user = user
        self.group_roles = group_roles
        self.user_perms = user_perms

    def __getattr__(self, attr_name: str) -> bool:
        """Return True if the user has the permission"""
        group_names = self.user.cached_groups
        if (group_ret := self.group_roles.has_perm(attr_name, group_names)) or (
            user_ret := self.user_perms.has_perm(attr_name, self.user)
        ):
            return True
        if group_ret is None and user_ret is None:
            raise KeyError(
                f"LINKCUBE ERROR: The permission attr_name '{attr_name}' could not be found in the group permission: '{', '.join(self.group_roles.group_perms.perms.keys())}' nor in the user permissions: '{', '.join(self.user_perms.perms.keys())}'"
            )
        return False


def PermissionsMixin_factory(group_roles: GroupRoles, user_perms: UserPerms) -> type:
    class PermissionsMixin:
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # user.has_perm is built into Django, call ours user.permissions
            setattr(self, GETTER_ATTR, PermissionGetter(self, group_roles, user_perms))

        def set_cached_groups(self, groups: list[str]):
            """Useful when using prefetch_related to pass in the already prefetched groups"""
            self._cached_groups = groups

        @property
        def cached_groups(self):
            """Warning 'groups' is a field name (M2M) so can't call this property 'groups'"""
            if not hasattr(self, '_cached_groups'):
                self._cached_groups = DjangoGroup.objects.filter(user=self).values_list(
                    'name', flat=True
                )
            return self._cached_groups

        def in_groups(self, *group_names: list[str]) -> bool:
            for group_name in group_names:
                if group_name in self.cached_groups:
                    return True
            return False

    return PermissionsMixin


# --- VIEW DECORATORS ---------------------------------------------------------


def fbv_user_can(attr_name: str) -> Callable:
    """
    Decorator for (F)unction (B)ased (V)iews that checks that the user has the
    given permission. Returns a 403 if they do not. Block permissions are hidden
    from the user, will only see this if they are trying something they shouldn't be.

    Use as follows:
        from djpp import permpp

        @permpp.user_can('view_foo')
        def view_view(request):
            ...
    """

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            getter = getattr(request.user, GETTER_ATTR)
            if getattr(getter, attr_name):
                return view_func(request, *args, **kwargs)
            raise PermissionDenied

        return _wrapped_view

    return decorator


def user_can(attr_name: str) -> Callable:
    """Class based view version of user_can decorator
    Use as follows:
        from djpp import permpp

        @permpp.user_can('view_foo')
        class FooView(generic.TemplateView):
    """
    return method_decorator(fbv_user_can(attr_name), name='dispatch')


# This code works but not very practical, rather use UserCanMixin below
# def fbv_user_can_test(func: Callable[[AbstractUser], bool]) -> Callable:
#     """
#     Like Django's user passes_test, but raises a 403 instead of redirecting the user.
#
#     Use as follows:
#         from djpp import permpp
#
#         @permpp.user_can_test(lambda user, pk: models.Foo.objects.get(pk=pk).user == user)
#         def view_view(request):
#             ...
#     """
#
#     def decorator(view_func):
#         @wraps(view_func)
#         def _wrapped_view(request, *args, **kwargs):
#             if func(request.user, *args, **kwargs):
#                 return view_func(request, *args, **kwargs)
#             raise PermissionDenied
#
#         return _wrapped_view
#
#     return decorator
#
#
# def user_can_test(attr_name: str) -> Callable:
#     """Class based view version of Django's user_passes_test decorator
#     Use as follows:
#         from djpp import permpp
#
#         @permpp.user_can_test(lambda user, pk: models.Foo.objects.get(pk=pk).user == user)
#         class FooView(generic.TemplateView):
#     """
#     return method_decorator(fbv_user_can_test(attr_name), name='dispatch')


# --- VIEW MIXINS -------------------------------------------------------------


class UserCanMixin:
    """
    Deny a request with a permission error if the test_func() method returns
    Also caches the get_object  so it doesnt hit the DB twice

    Example usage:
        from djpp import permpp

        class FooView(permpp.UserCanMixin, generic.DetailView):

            def can(self, user, *args, **kwargs):
                # here kwargs is probably {'pk': 123} for say a DetailView etc
                object = self.get_object()
                return object.user == user
    """

    def get_object(self, queryset=None):
        try:
            return self._cached_object
        except AttributeError:
            self._cached_object = super().get_object(queryset=queryset)
        return self._cached_object

    def can(self, user, *arg, **kwargs):
        raise NotImplementedError(
            f"'{self.__class__.__name__}' is missing the implementation of the test_func() method."
        )

    def dispatch(self, request, *args, **kwargs):
        user_passed_test = self.can(request.user, *args, **kwargs)
        if user_passed_test:
            return super().dispatch(request, *args, **kwargs)
        raise PermissionDenied


# --- REST PERMISSIONS --------------------------------------------------------
class SameUserPermission(drf_permissions.BasePermission):
    message = 'You are not authorised to edit this'

    def has_object_permission(self, request, _, obj):  # _ = view
        return obj.user == request.user


def permission_factory(attr_name, message=None):
    """
    Factory function to create a DRF permission class with custom attributes.
    """

    class DrfUserPermission(drf_permissions.BasePermission):
        _attr_name = attr_name
        _message = (
            message
            or f"Forbidden. User does not have the '{attr_name.replace('_', ' ')}' permission."
        )

        def has_permission(self, request, view):
            return getattr(request.user.can, self._attr_name, False)

    return DrfUserPermission


# Cache the result to avoid create many of the same objects, reduce memory footprint
@cache
def get_permission_classes(
    *attr_names,
    message: str | None = None,
    requires_login: bool = True,
    same_user: bool = False,
) -> list[Type[drf_permissions.BasePermission]]:
    """Generates a DRF permission classes.
    Use as follows:
        from djpp import permpp

        class FooView(generics.CreateAPIView):
            permission_classes = permpp.get_permission_classes('edit_foo')
            permission_classes = permpp.get_permission_classes('edit_foo', 'edit_bar')
            permission_classes = permpp.get_permission_classes('edit_foo', message='You shall not pass!')
            permission_classes = permpp.get_permission_classes('edit_foo', same_user=True)
    """

    permission_classes = []
    if requires_login:
        permission_classes.append(drf_permissions.IsAuthenticated)
    if same_user:
        permission_classes.append(SameUserPermission)
    for attr_name in attr_names:
        permission_classes.append(permission_factory(attr_name, message))
    return permission_classes
