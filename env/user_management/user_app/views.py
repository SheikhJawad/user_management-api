from django.contrib.auth import authenticate
from rest_framework import generics,permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegisterSerializer, LoginSerializer
from .models import *
from rest_framework.views import APIView
from rest_framework.permissions import  IsAuthenticated
from  rest_framework import status



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
class UserDeleteView(generics.DestroyAPIView):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        user = self.get_object()
        user.delete()
        return Response({'message': 'User deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)