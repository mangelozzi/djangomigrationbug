from django.db import models

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.contrib.auth.models import Group as DjangoGroup
from django.db import models
from django.utils.translation import gettext_lazy as _
from . import modelpp
from plug.user import UserMixin



class UserManager(BaseUserManager):
    """Define a model manager for User model with no username field."""

    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular User with the given email and password."""
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)


class User(UserMixin, AbstractUser, modelpp.NiceNameMixin):
    """
    Requirements:
    - Must be defined in models.py, due to the way settings.AUTH_USER_MODEL is defined
    """

    objects = UserManager()

    username = None
    email = models.EmailField('email address', unique=True)
    is_staff = models.BooleanField(
        'admin access',
        default=False,
        help_text='Designates whether the user can log into this admin site.',
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ('first_name',)

    def __str__(self):
        return self.get_full_name()

    class Meta:
        db_table = 'auth_user'


    @property
    def cached_groups(self):
        """Warning 'groups' is a field name (M2M) so can't call this property 'groups'"""
        if not hasattr(self, '_cached_groups'):
            self._cached_groups = DjangoGroup.objects.filter(user=self).values_list(
                'name', flat=True
            )
        return self._cached_groups

    def in_groups(self, *names):
        for name in names:
            if name in self.cached_groups:
                return True
        return False


class Group(DjangoGroup):
    """Instead of trying to get new user under existing `Aunthentication and Authorization`
    banner, create a proxy group model under our Accounts app label.
    Refer to: https://github.com/tmm/django-username-email/blob/master/cuser/admin.py
    """

    class Meta:
        verbose_name = 'group'
        verbose_name_plural = 'groups'
        proxy = True
