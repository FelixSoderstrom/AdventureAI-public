# AdventureAI Logger

This module provides a centralized logging system for the AdventureAI application. It allows for consistent logging across different components of the application.

## Logger Overview

The logging system creates log files in a `logs` directory at the root of the project. Log files are named with the date (`adventure_ai_YYYY-MM-DD.log`) and are rotated when they reach 10MB in size, keeping 5 backup files.

## How to Use

### Using the Loggable Base Class (Recommended)

For even simpler integration, you can inherit from the `Loggable` base class:

```python
from app.api.logger.loggable import Loggable

class MyClass(Loggable): # Inherit the logger
    def __init__(self):
        super().__init__()  # Initialize the logger
        self.logger.info("Now you can log stuff!")
        
    def my_method(self):
        self.logger.debug("You can even log over here!")
```

### Pre-Configured Loggers (Legacy Approach)

The following pre-configured loggers are available but the class-based approach is preferred:

- `db_logger`: For database operations
- `api_logger`: For general API operations
- `game_logger`: For game-related activities
- `auth_logger`: For authentication and authorization activities
- `general_logger`: For general application logging

```python
from app.api.logger.logger import db_logger

# Then use it for logging
db_logger.info("This is kinda lame.")
db_logger.error("But useful when we're not in a class!'")
```

### Creating Custom Loggers

If you need a standalone custom logger for a specific component:

```python
from app.api.logger.logger import get_logger

# Create a custom logger
my_logger = get_logger("app.my_component")
my_logger.info("My component is working")
```

## Available Log Levels

The loggers support the standard Python logging levels:

- `debug`: Detailed debug information
- `info`: General information about the operation of the application
- `warning`: Warnings about potential issues
- `error`: Errors that occurred but didn't stop the application
- `critical`: Critical errors that might cause the application to terminate

## Best Practices

1. Use object-oriented approach with class-specific loggers for better context
2. Include meaningful information in log messages
3. Use appropriate log levels
4. Don't log sensitive information (passwords, tokens, etc.)


## Avoiding Excessive Logging

- Don't log sensitive data (passwords, full tokens, etc.)
- Use debug level for high-volume operations
- Avoid logging large payloads (AI responses, image data)
- Be careful with string formatting in hot paths 