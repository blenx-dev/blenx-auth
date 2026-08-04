class AuthRouterConfig:
    def __init__(self, *
        user_read_schema: Type[BaseUserRead] = UserRead,
        user_create_schema: Type[BaseRegisterRequest] = RegisterRequest,
    ):
        """Configuration for schema overrides in AuthRouter."""

        self.user_read_schema = user_read_schema
        self.user_create_schema = user_create_schema


class AuthRouter(APIRouter):
    def __init__(self, config: AuthRouterConfig):
        super().__init__()
        self.config = config

    def include_routes(self):
        """Wire up routes using provided schema configurations."""

        # Registration endpoint with custom schemas
        self.add_endpoint(
            path="/register",
            method="POST",
            request_model=self.config.user_create_schema,
            response_model=self.config.user_read_schema,
            handler=self._register
        )

        # Login endpoint
        self.add_endpoint(
            path="/login",
            method="POST",
            request_model=LoginRequest,
            response_model=TokenResponse,
            handler=self._login
        )