# Simple HTTP Server

## Technical Skills Demonstrated

### Network & Socket Programming
- Implemented TCP server using POSIX socket API
- Applied non-blocking I/O with `fcntl()`
- Used `setsockopt()` for socket configuration (SO_REUSEADDR)

### TCP Server Architecture
- Built complete HTTP request/response lifecycle
- Managed concurrent client connections
- Created clean connection state abstraction

### Event Loop Pattern
- Used `poll()` for I/O multiplexing
- Implemented non-blocking event-driven architecture
- Applied reactor pattern for handling I/O events

### HTTP Protocol Features
- Parsed HTTP requests and generated proper responses
- Supported GET and POST methods
- Implemented path-based routing
- Added content compression with gzip
- Handled file operations (read/write)

### Key Implementation Details
- Connection state management
- Error handling for network operations
- Command-line configuration
- HTTP header parsing and generation
