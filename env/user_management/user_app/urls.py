from django.urls import path
from . import views
urlpatterns = [
    #   path('register/', views.UserRegisterView.as_view(), name='user-register'),
    #   path('login/', views.TokenObtainPairView.as_view(), name='token-obtain-pair'),
    #   path('token/refresh/', views.TokenRefreshView.as_view(), name='token-refresh'),
    #   path('token/verify/', views.TokenVerifyView.as_view(), name='token-verify'),
     path('register/', views.RegisterView.as_view(), name='register'),
     path('login/', views.LoginView.as_view(), name='login'),
     path('logout/',views.LogoutView.as_view(),name='logout'),
    
    
]
