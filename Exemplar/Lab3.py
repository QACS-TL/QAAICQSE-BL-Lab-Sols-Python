try:
    from .user_manager import UserManager
except ImportError:
    from user_manager import UserManager

__all__ = ["UserManager"]