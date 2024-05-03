from django.db import models

from .perm import PermissionsMixin


class UserMixin(PermissionsMixin, models.Model):
    # custom_field = models.CharField('Custom field', max_length=250)
    is_terminal = models.BooleanField(default=False)

    class Meta:
        abstract = True



class UserAdminMixin:
    custom_list_display = []
    custom_list_filter = []
    custom_section_fields = []

    def get_queryset(self, request):
        """Filter out terminals from the User list in the admin, however don't filter
        it if click on the specific item to change it, else will say it doesnt exists.
        """
        queryset = super().get_queryset(request)
        detail_request = any(char.isdigit() for char in request.path)
        if not detail_request or not request.user.is_developer:
            # i.e. Always filter a list view, or if not an developer
            queryset = queryset.filter(is_terminal=False)
        return queryset
