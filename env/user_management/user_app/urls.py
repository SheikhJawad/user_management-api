from django.urls import path
from . import views

urlpatterns = [
    
     path('register/', views.UserRegisterView.as_view(), name='register'),
     path('login/', views.LoginView.as_view(), name='login'),
     path('logout/',views.LogoutView.as_view(),name='logout'),
     path('password-reset/', views.PasswordResetRequestView.as_view(), name='password_reset_request'),
     path('password-change/', views.PasswordChangeView.as_view(), name='password-change'),
     path('password-reset/confirm/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
     path('user-detail-token/', views.RefreshTokenView.as_view(), name='refresh-token'),
     path('user/<int:pk>/', views.UserUpdateDeleteView.as_view(), name='user-update-delete'),

     
]
     
    





