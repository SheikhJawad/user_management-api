from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.core import mail
from .models import UserToken,User,UserProfile,LoginAttempt, LoginSettings
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
User = get_user_model()
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from django.utils import timezone
from unittest.mock import patch

class RegisterViewTestCase(APITestCase):
    def test_register_user(self):
        url = reverse('register')
        data = {
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'TestPassword123!',
            'confirm_password': 'TestPassword123!'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(username='testuser').exists())

class LoginViewTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@outlook.com.com',
            password='TestPassword123!'
        )
        self.url = reverse('login')

    def test_login_user(self):
        data = {
            'username': 'testuser',
            'password': 'TestPassword123!'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('refresh', response.data)
        self.assertTrue(UserToken.objects.filter(user=self.user).exists())

    def test_login_invalid_credentials(self):
        data = {
            'username': 'testuser',
            'password': 'WrongPassword!'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)



class LogoutViewTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='user',
            email='testuser@gmail.com',
            password='Password123!'
        )
        
        self.refresh_token = RefreshToken.for_user(self.user)
      
        self.user_token = UserToken.objects.create(
            user=self.user,  
            access_token=str(self.refresh_token.access_token),
            refresh_token=str(self.refresh_token)
        )
        self.url = reverse('logout')

    def test_logout_user(self):
        response = self.client.post(self.url, {'refresh_token': str(self.refresh_token)}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Logged out successfully')

    def test_logout_invalid_token(self):
        response = self.client.post(self.url, {'refresh_token': 'invalid_token'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid refresh token')

    def test_logout_missing_token(self):
        response = self.client.post(self.url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Refresh token is required')


class PasswordResetRequestViewTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123!'
        )
        self.url = reverse('password_reset_request')

    def test_password_reset_request(self):
        data = {'email': 'testuser@example.com'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('Password Reset Request', mail.outbox[0].subject)

    def test_password_reset_request_invalid_email(self):
        data = {'email': 'invalid@example.com'}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmViewTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123!'
        )
        self.token = default_token_generator.make_token(self.user)
        self.user_profile = UserProfile.objects.create(user=self.user, password_reset_token=self.token)
        self.url = reverse('password_reset_confirm')

    def test_password_reset_confirm(self):
        data = {
            'token': self.token,
            'new_password': 'NewPassword123!'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('NewPassword123!'))

    def test_password_reset_confirm_invalid_token(self):
        data = {
            'token': 'invalidtoken',
            'new_password': 'NewPassword123!'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class PasswordChangeViewTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123!'
        )
        self.client.force_authenticate(user=self.user)
        self.url = reverse('password-change')

    def test_password_change(self):
        data = {
            'current_password': 'TestPassword123!',
            'new_password': 'NewPassword123!',
            'confirm_password': 'NewPassword123!'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('NewPassword123!'))

    def test_password_change_invalid_current_password(self):
        data = {
            'current_password': 'WrongPassword!',
            'new_password': 'NewPassword123!',
            'confirm_password': 'NewPassword123!'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class RefreshTokenViewTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123!'
        )
        self.refresh = RefreshToken.for_user(self.user)
        self.url = reverse('refresh-token')

    def test_refresh_token(self):
        data = {'refresh': str(self.refresh)}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_refresh_token_missing(self):
        data = {}
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class UserUpdateDeleteViewTestCase(APITestCase):
    def setUp(self):

        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123!'
        )
    
        self.superuser = User.objects.create_superuser(
            username='superuser',
            email='superuser@example.com',
            password='SuperPassword123!'
        )
       
        self.client.force_authenticate(user=self.user)
        self.url = reverse('user-update-delete', kwargs={'pk': self.user.id})
        self.superuser_url = reverse('user-update-delete', kwargs={'pk': self.superuser.id})

    def test_update_user(self):
     
        data = {'first_name': 'Updated', 'last_name': 'User'}
        response = self.client.patch(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.last_name, 'User')

    def test_delete_user(self):
     
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(User.objects.filter(id=self.user.id).exists())

    def test_delete_superuser(self):
     
        self.client.force_authenticate(user=self.superuser)
      
        response = self.client.delete(self.superuser_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertTrue(User.objects.filter(id=self.superuser.id).exists())




User = get_user_model()

@override_settings(
    ROOT_URLCONF='user_management.urls',  
    REST_FRAMEWORK={
        'DEFAULT_AUTHENTICATION_CLASSES': (
            'rest_framework_simplejwt.authentication.JWTAuthentication',
        )
    }
)
class LoginViewTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.login_url = '/api/login/'  # Replace with your actual login URL path
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        LoginSettings.objects.create(max_attempts=3, lockout_duration=30)

    def test_successful_login(self):
        response = self.client.post(self.login_url, {'username': 'testuser', 'password': 'testpass123'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('refresh', response.data)
        self.assertIn('message', response.data)
        self.assertEqual(response.data['message'], 'Logged in successfully')

    def test_failed_login(self):
        response = self.client.post(self.login_url, {'username': 'testuser', 'password': 'wrongpass'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Invalid credentials')

    def test_login_attempts_tracking(self):
        self.client.post(self.login_url, {'username': 'testuser', 'password': 'wrongpass'})
        self.assertEqual(LoginAttempt.objects.count(), 1)
        self.assertFalse(LoginAttempt.objects.first().successful)

    def test_account_lockout(self):
        for _ in range(3):
            self.client.post(self.login_url, {'username': 'testuser', 'password': 'wrongpass'})
        
        response = self.client.post(self.login_url, {'username': 'testuser', 'password': 'testpass123'})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Account locked. Try again later.')

    def test_lockout_expiry(self):
        for _ in range(3):
            self.client.post(self.login_url, {'username': 'testuser', 'password': 'wrongpass'})
    
        future_time = timezone.now() + timezone.timedelta(minutes=31)
        with patch('django.utils.timezone.now', return_value=future_time):
            response = self.client.post(self.login_url, {'username': 'testuser', 'password': 'testpass123'})
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_login_with_nonexistent_user(self):
        response = self.client.post(self.login_url, {'username': 'nonexistentuser', 'password': 'somepass'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Invalid credentials')

    def test_login_attempt_ip_address(self):
        self.client.post(self.login_url, {'username': 'testuser', 'password': 'wrongpass'})
        login_attempt = LoginAttempt.objects.first()
        self.assertIsNotNone(login_attempt.ip_address)

class LoginSettingsTestCase(TestCase):
    def test_login_settings_creation(self):
        settings = LoginSettings.get_settings()
        self.assertEqual(settings.max_attempts, 5)  
        self.assertEqual(settings.lockout_duration, 30)  

    def test_login_settings_update(self):
        settings = LoginSettings.get_settings()
        settings.max_attempts = 3
        settings.lockout_duration = 60
        settings.save()

        updated_settings = LoginSettings.get_settings()
        self.assertEqual(updated_settings.max_attempts, 3)
        self.assertEqual(updated_settings.lockout_duration, 60)

class LoginAttemptTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass123')

    def test_get_recent_attempts(self):
    
        LoginAttempt.objects.create(user=self.user, successful=False)
        LoginAttempt.objects.create(user=self.user, successful=False)
        LoginAttempt.objects.create(user=self.user, successful=True)

      
        old_attempt = LoginAttempt.objects.create(user=self.user, successful=False)
        old_attempt.timestamp = timezone.now() - timezone.timedelta(minutes=31)
        old_attempt.save()

        recent_attempts = LoginAttempt.get_recent_attempts(self.user, minutes=30)
        self.assertEqual(recent_attempts.count(), 2)  # Only the recent failed attempts