from django.urls import path
from . import views

urlpatterns = [
    
     path('register/', views.RegisterView.as_view(), name='register'),
     path('login/', views.LoginView.as_view(), name='login'),
     path('logout/',views.LogoutView.as_view(),name='logout'),
     path('password-reset/', views.PasswordResetRequestView.as_view(), name='password_reset_request'),
     path('password-change/', views.PasswordChangeView.as_view(), name='password-change'),
     path('password-reset/confirm/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
     path('user-detail-token/', views.RefreshTokenView.as_view(), name='refresh-token'),
     path('user/<int:pk>/', views.UserUpdateDeleteView.as_view(), name='user-update-delete'),
   #   path('track-button-click/', views.track_button_click, name='track_button_click'),
     #  path('metrics/', exports.ExportToDjangoView, name='prometheus-metrics'),
     
]
     
    




# from django.urls import path, re_path
# from rest_framework import permissions
# from drf_yasg.views import get_schema_view
# from drf_yasg import openapi

# schema_view = get_schema_view(
#     openapi.Info(
#         title="Your API Title",
#         default_version='v1',
#         description="Detailed description of your API",
#         terms_of_service="https://www.google.com/policies/terms/",
#         contact=openapi.Contact(email="contact@yourdomain.com"),
#         license=openapi.License(name="BSD License"),
#     ),
#     public=True,
#     permission_classes=(permissions.AllowAny,),
# )

# urlpatterns = [
    
#     re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
#     path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
#     path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
# ]
