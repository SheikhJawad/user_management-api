from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.core import mail
from .models import UserToken,User,UserProfile
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from rest_framework import status
from .serializers import RegisterSerializer, LoginSerializer, PasswordResetRequestSerializer, PasswordResetConfirmSerializer, CurrentPasswordSerializer, PasswordUpdateSerializer, UserUpdateSerializer
User = get_user_model()

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
            email='testuser@example.com',
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
        # self.assertIn('access', response.data)
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
        # Create a user
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123!'
        )
        # Generate a refresh token for the user
        self.refresh_token = RefreshToken.for_user(self.user)
        # Save the refresh token to the UserToken model with the user field
        self.user_token = UserToken.objects.create(
            user=self.user,  # Add this line to set the user
            access_token=str(self.refresh_token.access_token),
            refresh_token=str(self.refresh_token)
        )
        # URL for the logout view
        self.url = reverse('logout')

    def test_logout_user(self):
        # Test logging out with a valid refresh token
        response = self.client.post(self.url, {'refresh_token': str(self.refresh_token)}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Logged out successfully')

    def test_logout_invalid_token(self):
        # Test logging out with an invalid refresh token
        response = self.client.post(self.url, {'refresh_token': 'invalid_token'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid refresh token')

    def test_logout_missing_token(self):
        # Test logging out with a missing refresh token
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
        # Create a regular user
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123!'
        )
        # Create a superuser for testing permission restrictions
        self.superuser = User.objects.create_superuser(
            username='superuser',
            email='superuser@example.com',
            password='SuperPassword123!'
        )
        # Authenticate the regular user for testing
        self.client.force_authenticate(user=self.user)
        self.url = reverse('user-update-delete', kwargs={'pk': self.user.id})
        self.superuser_url = reverse('user-update-delete', kwargs={'pk': self.superuser.id})

    def test_update_user(self):
        # Test updating the user
        data = {'first_name': 'Updated', 'last_name': 'User'}
        response = self.client.patch(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.last_name, 'User')

    def test_delete_user(self):
        # Test deleting the user
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(User.objects.filter(id=self.user.id).exists())

    def test_delete_superuser(self):
        # Authenticate as superuser for this test
        self.client.force_authenticate(user=self.superuser)
        # Test that superuser cannot be deleted
        response = self.client.delete(self.superuser_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertTrue(User.objects.filter(id=self.superuser.id).exists())