"""
Base class for adding logging capabilities to classes.
Classes that inherit from Loggable will automatically get a self.logger instance.
"""

from app.api.logger.logger import get_logger


class Loggable:
    """
    A mixin class that adds logging capabilities to any class that inherits from it.

    Example usage:
    ```
    class Class(Loggable):
        def __init__(self):
            super().__init__()  # Initialize the logger
            self.logger.info("Class initialized")
    ```
    """

    def __init__(self):
        """
        Initialize the logger for this class.
        The logger name will be the fully qualified class name.
        """
        self.logger = get_logger(
            f"{self.__class__.__module__}.{self.__class__.__name__}"
        )
