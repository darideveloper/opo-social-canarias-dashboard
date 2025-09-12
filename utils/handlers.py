from rest_framework.views import exception_handler


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    # Now add the HTTP status code to the response.
    if response is not None:
        original_data = response.data
        response.data = {}
        response.data['status'] = "error"
        details = original_data.get('detail', None)
        if details:
            del original_data['detail']
            response.data['message'] = str(details)
        else:
            response.data['message'] = "Invalid data"
        response.data['data'] = original_data
            
    return response