from django.contrib import admin
from .models import Voter, Party, Vote, RegisteredUser


# Register with admin app
class RegisterUserAdmin(admin.ModelAdmin):
    list_display = [field.name for field in RegisteredUser._meta.get_fields() if field.name != "id"]


admin.site.register(RegisteredUser, RegisterUserAdmin)
admin.site.register(Voter)
admin.site.register(Party)
admin.site.register(Vote)
