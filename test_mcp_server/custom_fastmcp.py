from mcp.server.fastmcp import FastMCP
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware

class HeaderCaptureMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, custom_fastmcp):
        super().__init__(app)
        self.custom_fastmcp = custom_fastmcp
        
    async def dispatch(self, request, call_next):
        # Store headers from the request
        self.custom_fastmcp.request_headers = dict(request.headers)
        response = await call_next(request)
        return response

class CustomFastMCP(FastMCP):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.request_headers = {}
        
    def sse_app(self):
        app = super().sse_app()
        
        # Add middleware to capture headers
        app.user_middleware.insert(0, Middleware(HeaderCaptureMiddleware, custom_fastmcp=self))
        app.middleware_stack = None  # Force rebuild of middleware stack
            
        return app
    
    # Method to access headers
    def get_headers(self):
        return self.request_headers