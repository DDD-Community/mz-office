from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response

def index(request):
    return render(request, 'index.html')

# API Docs 자동 버전
class OnePersonAPIView(APIView):
    def get(self, request, format=None):
        data = {
            "id": 1,
            "name": "integerji",
            "age": 28,
            "city": "Gwanak-gu"
        }
        return Response(data)

    def post(self, request, format=None):
        data = {
            "id": 2,
            "name": "nayoung0",
            "age": 29,
            "city": "Gwanak-gu"
        }
        return Response(data)

# API Docs 수동 버전
class TwoPersonAPIView(APIView):
    """
    OnePersonAPIView

    A description of your API endpoint.
    """

    def get(self, request, format=None):
        """
        Retrieve one person's information.

        This endpoint retrieves information about a person.

        Parameters:
        - id: The ID of the person.

        Responses:
        - 200: Successfully retrieved person information.
        - 404: Person not found.
        """
        data = {
            "id": 3,
            "name": "지정수",
            "age": 25,
            "city": "Gwanak-gu"
        }
        return Response(data)

    def post(self, request, format=None):
        """
        Create a new person.

        This endpoint creates a new person with the provided information.

        Parameters:
        - name: The name of the person.
        - age: The age of the person.
        - city: The city where the person lives.

        Responses:
        - 201: Successfully created a new person.
        - 400: Invalid input data.
        """
        data = {
            "id": 4,
            "name": "강나영",
            "age": 26,
            "city": "Gwanak-gu"
        }
        return Response(data)
