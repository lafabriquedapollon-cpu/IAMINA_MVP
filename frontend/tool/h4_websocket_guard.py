"""Qualification-only WebSocket refusal, not a production security boundary."""
def attach_websocket_guard(context, blocked):
    def refuse(_route):
        # Playwright mocks routed sockets unless connect_to_server is called.
        # Do not retain URLs or query strings, and never connect upstream.
        blocked.append("websocket_attempt")
    context.route_web_socket("**/*", refuse)
