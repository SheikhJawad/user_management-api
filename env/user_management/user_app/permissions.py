# from rest_framework import permissions

# class IsAdminOrOwner(permissions.BasePermission):
#     """
#     Custom permission to only allow admins or the user themselves to update/delete their data.
#     """

#     def has_object_permission(self, request, view, obj):
#         # Allow update/delete if the user is an admin or the owner of the account
#         return request.user.is_staff or obj == request.user
