from django.contrib.auth import authenticate
from rest_framework import generics,permissions
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegisterSerializer, LoginSerializer,PasswordResetRequestSerializer, PasswordResetConfirmSerializer,CurrentPasswordSerializer,PasswordUpdateSerializer
from .models import *
from django.contrib.auth.tokens import default_token_generator
from rest_framework import status
from .serializers import PasswordResetConfirmSerializer
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
User = get_user_model()



class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user is None:
            return Response({'error': 'Invalid credentials'}, status=400)

        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)

        # Store the tokens in the UserToken model
        user_token, created = UserToken.objects.get_or_create(user=user)
        user_token.access_token = access
        user_token.refresh_token = str(refresh)
        user_token.is_logged_in = True
        user_token.save()

        return Response({
            'message': 'Logged in successfully', 
             'refresh': user.token.refresh_token,
            
            
        })
    
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            user_token = UserToken.objects.get(user=request.user)
            # Log out the user and invalidate the token
            user_token.logout()
        except UserToken.DoesNotExist:
            return Response({'error': 'User token does not exist'}, status=400)

        return Response({'message': 'Logged out successfully'})
# class UserDeleteView(generics.DestroyAPIView):
#     queryset = User.objects.all()
#     permission_classes = [IsAuthenticated]

#     def delete(self, request, *args, **kwargs):
#         user = self.get_object()
#         user.delete()
#         return Response({'message': 'User deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)




class PasswordResetRequestView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                token = default_token_generator.make_token(user)

                user_profile, created = UserProfile.objects.get_or_create(user=user)
                user_profile.password_reset_token = token
                user_profile.save()

                reset_link = f"http://127.0.0.1:8000/password-reset/confirm/?token={token}"

                send_mail(
                    'Password Reset Request',
                    f'Click the link to reset your password: {reset_link}',
                    settings.EMAIL_HOST_USER,
                    [email],
                    fail_silently=False,
                )
                return Response({'detail': 'Password reset link sent.'}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'detail': 'User with this email does not exist.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class PasswordResetConfirmView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']
            
            try:
                
                user_profile = UserProfile.objects.get(password_reset_token=token)
                user = user_profile.user

        
                if default_token_generator.check_token(user, token):
                    user.set_password(new_password)
                    user.save()

                  
                    user_profile.password_change_count += 1
                    user_profile.password_reset_token = '' 
                    user_profile.save()

                    return Response({'detail': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
                else:
                    return Response({'detail': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)
            except (UserProfile.DoesNotExist):
                return Response({'detail': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    
class PasswordChangeView(APIView):
    def post(self, request, *args, **kwargs):
      
        current_password_serializer = CurrentPasswordSerializer(data=request.data, context={'request': request})
        if not current_password_serializer.is_valid():
            return Response(current_password_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
       
        password_update_serializer = PasswordUpdateSerializer(data=request.data, context={'request': request})
        if not password_update_serializer.is_valid():
            return Response(password_update_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        password_update_serializer.save()
        return Response({'detail': 'Password updated successfully.'}, status=status.HTTP_200_OK)



class RefreshTokenView(APIView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response({'detail': 'Refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            
            refresh = RefreshToken(refresh_token)
            access_token = refresh.access_token

         
            user_id = access_token.payload.get('user_id')
            user = User.objects.get(id=user_id)

           
            return Response({
                'access': str(access_token),
                'refresh': str(refresh),
                'user_id': user.id,
                'username': user.username,
                'email': user.email
            }, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        


