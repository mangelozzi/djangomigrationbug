1. Check `accounts/migrations/0001_initial.py`
    - You will see this line `bases=(plug.permpp.PermissionsMixin_factory.<locals>.PermissionsMixin, models.Model, accounts.modelpp.NiceNameMixin),`
    - I has an error `<locals>`
2. Delete the above migrations file
3. Run `python manage.py makemigrations`
4. The file above with the error will be created.
