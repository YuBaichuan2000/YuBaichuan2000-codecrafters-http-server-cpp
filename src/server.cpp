#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sstream>
#include <assert.h>
#include <map>
#include <fstream>

std::string g_directory = "/tmp"; 

std::vector<std::string> split_message(const std::string &message, const std::string& delim) {
  std::vector<std::string> tokens;
  // Check for empty inputs to prevent processing errors
  if (message.empty() || delim.empty()) {
    return tokens;
  }
  
  std::stringstream ss = std::stringstream{message};
  std::string line;
  while (getline(ss, line, *delim.begin())) {
    tokens.push_back(line);
    // Only ignore if not at EOF
    if (!ss.eof()) {
      ss.ignore(delim.length() - 1);
    }
  }
  return tokens;
}

std::string get_path(std::string request) {
  // Added safety checks
  std::vector<std::string> toks = split_message(request, "\r\n");
  if (toks.empty()) {
    return "/"; // Default path if no request line
  }
  
  std::vector<std::string> req_toks = split_message(toks[0], " ");
  if (req_toks.size() < 2) {
    return "/"; // Default path if no path token
  }
  
  return req_toks[1];
}

std::string get_file(std::string request) {
  // Added safety checks
  std::vector<std::string> toks = split_message(request, "\r\n");
  if (toks.empty()) {
    return "/"; // Default path if no request line
  }
  
  std::vector<std::string> path_toks = split_message(toks[0], " ");
  if (path_toks.size() < 2) {
    return "/"; // Default path if no path token
  }

  std::string filename = path_toks[1].substr(7);
  std::string filepath = g_directory + "/" + filename;

  // Read and return the file content
  std::ifstream file(filepath, std::ios::binary);
  if (!file) {
      return ""; // File not found or couldn't be opened
  }
  
  // Read the entire file content into a string
  std::stringstream buffer;
  buffer << file.rdbuf();
  
  return buffer.str();
}

bool write_file(const std::string& filename, const std::string& content) {
  // Construct the full file path
  std::string filepath = g_directory + "/" + filename;
  
  std::cout << "Writing file to: " << filepath << std::endl;
  
  // Open the file for writing
  std::ofstream file(filepath, std::ios::binary);
  if (!file) {
    std::cerr << "Could not open file for writing: " << filepath << std::endl;
    return false;
  }
  
  // Write the content
  file << content;
  
  // Check if the write operation was successful
  if (!file) {
    std::cerr << "Error writing to file: " << filepath << std::endl;
    return false;
  }
  
  file.close();
  return true;
}

std::string get_agent(std::string request) {
  std::vector<std::string> toks = split_message(request, "\r\n");
  std::string agent;

  for (std::string tok : toks) {
    if (tok.find("User-Agent: ") == 0) {
      agent = tok.substr(12);
      break;
    }
  }
  return agent;
}

std::string get_method(std::string request) {
  std::vector<std::string> toks = split_message(request, "\r\n");

  std::vector<std::string> req_toks = split_message(toks[0], " ");

  return req_toks[0];
}

std::string get_request_body(const std::string& request) {
  // Find the end of headers
  size_t header_end = request.find("\r\n\r\n");
  if (header_end == std::string::npos) {
    return "";
  }
  
  // The body starts after the headers
  return request.substr(header_end + 4);
}

// set socket to non-blocking mode
void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        std::cerr << "fcntl F_GETFL error: " << strerror(errno) << std::endl;
        return;
    }
    
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        std::cerr << "fcntl F_SETFL error: " << strerror(errno) << std::endl;
    }
}

struct Conn {
    int fd = -1;
    std::string incoming;
    std::string outgoing;  
    bool want_read = true;
    bool want_write = false;
    bool want_close = false;
    
    Conn(int socket_fd) : fd(socket_fd) {}
};

// Function to generate a response based on the request
std::string generate_response(const std::string& client_msg) {
  std::string path = get_path(client_msg);
  std::string agent = get_agent(client_msg);
  std::string method = get_method(client_msg);
  std::vector<std::string> split_paths = split_message(path, "/");
  
  std::cout << "Received path: " << path << std::endl;
  std::cout << "Received agent: " << agent << std::endl;

  if (method == "GET") {
    if (path == "/") {
      return "HTTP/1.1 200 OK\r\n\r\n";
    } else if (split_paths.size() > 1 && split_paths[1] == "echo") {
      if (split_paths.size() > 2) {
        return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " 
              + std::to_string(split_paths[2].length()) + "\r\n\r\n" + split_paths[2];
      } else {
        return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n";
      }
    } else if (split_paths.size() > 1 && split_paths[1] == "files") {
      if (split_paths.size() > 2) {
        // This is a file request
        std::string content = get_file(client_msg);
        if (content.empty()) {
          return "HTTP/1.1 404 Not Found\r\n\r\n";
        }
        return "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " 
              + std::to_string(content.length()) + "\r\n\r\n" + content;
      } 
    } else if (split_paths.size() > 1 && split_paths[1] == "user-agent") {
      return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " 
            + std::to_string(agent.length()) + "\r\n\r\n" + agent;
    } else {
      return "HTTP/1.1 404 Not Found\r\n\r\n";
    }
  } else if (method == "POST") {
    if (split_paths.size() > 1 && split_paths[1] == "files") {
      if (split_paths.size() > 2) {
        // This is a file upload request
        std::string filename = path.substr(7);  // Remove "/files/" prefix
        std::string content = get_request_body(client_msg);
        
        // Write the content to the file
        if (write_file(filename, content)) {
          return "HTTP/1.1 201 Created\r\n\r\n";
        } 
    } 
  }
  }
  
}

bool try_process_request(Conn* conn) {
  // Check if conn is valid
  if (!conn) {
    return false;
  }

  // Check if we have a complete HTTP request
  size_t header_end = conn->incoming.find("\r\n\r\n");
  if (header_end == std::string::npos) {
    return false; // Need more data
  }

  // We have a complete HTTP request
  std::string request = conn->incoming;

  std::string response = generate_response(request);
  conn->outgoing += response;

  conn->want_read = false;
  conn->want_write = true;

  conn->incoming.clear();
  return true;
}

// Function to read and parse the client request
void handle_read(Conn* conn) {
  // Check if conn is valid
  if (!conn) {
    return;
  }

  char buffer[4096] = {0}; // Increased buffer size
  
  int bytes_read = read(conn->fd, buffer, sizeof(buffer)-1);
  
  if (bytes_read <= 0) {
    if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      // Not ready, not an error
      return;
    }
    
    // Error or client disconnected
    if (bytes_read < 0) {
      std::cerr << "Failed to read from client: " << strerror(errno) << std::endl;
    } else {
      std::cout << "Client disconnected" << std::endl;
    }
    
    conn->want_close = true;
    return;
  }

  // Append data to buffer
  conn->incoming.append(buffer, bytes_read);

  std::cout << "Received request:\n" << buffer << std::endl;

  try_process_request(conn);
}

// Function to send the response to the client
void handle_write(Conn* conn) {
  // Check if conn is valid
  if (!conn) {
    return;
  }

  if (conn->outgoing.empty()) {
    conn->want_write = false;
    conn->want_read = true;  // Ready to read the next request
    return;
  }

  int bytes_sent = write(conn->fd, conn->outgoing.c_str(), conn->outgoing.size());
  if (bytes_sent < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // Not ready to write
      return;
    }
    
    std::cerr << "Failed to send response: " << strerror(errno) << std::endl;
    conn->want_close = true;
    return;
  }
  
  // Remove sent data from buffer
  conn->outgoing.erase(0, bytes_sent);

  if (conn->outgoing.empty()) {
    conn->want_write = false;
    conn->want_read = true;
  }
}

// Function to accept a client connection
Conn* accept_client(int server_fd) {
  struct sockaddr_in client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  
  // Initialize to zero
  memset(&client_addr, 0, sizeof(client_addr));
    
  int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
    
  if (client_fd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // No connections waiting
      return nullptr;
    }
    std::cerr << "Accept error: " << strerror(errno) << std::endl;
    return nullptr;
  }
    
  // Print client information
  char client_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
  std::cout << "New connection from " << client_ip << ":" << ntohs(client_addr.sin_port) << std::endl;
    
  // Set client socket to non-blocking mode
  set_nonblocking(client_fd);
    
  // Create and return new connection
  return new Conn(client_fd);
}

int main(int argc, char **argv) {
  // Flush after every std::cout / std::cerr
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;
  
  std::cout << "Logs from your program will appear here!\n";

  // Parse the directory argument
  std::string directory = "/tmp"; // Default directory
  for (int i = 1; i < argc; i++) {
    if (std::string(argv[i]) == "--directory" && i + 1 < argc) {
      directory = argv[i+1];
      break;
    }
  }

  g_directory = directory;

  std::cout << "Using directory: " << g_directory << std::endl;

  // TCP connection
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
   std::cerr << "Failed to create server socket\n";
   return 1;
  }
  
  // Since the tester restarts your program quite often, setting SO_REUSEADDR
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    std::cerr << "setsockopt failed\n";
    return 1;
  }
  
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr)); // Initialize properly
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(4221);
  
  if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
    std::cerr << "Failed to bind to port 4221\n";
    return 1;
  }

  set_nonblocking(server_fd);
  
  int connection_backlog = 5;
  if (listen(server_fd, connection_backlog) != 0) {
    std::cerr << "listen failed\n";
    return 1;
  }

  // Changed from vector to map for safer access by file descriptor
  std::map<int, Conn*> fd_to_conn;
  
  // Accept concurrent client connections
  while (true) {
    std::vector<struct pollfd> poll_fds;

    // Add the server socket
    struct pollfd server_pfd = {server_fd, POLLIN, 0};
    poll_fds.push_back(server_pfd);

    // Add all active client connections
    for (const auto& pair : fd_to_conn) {
      int fd = pair.first;
      Conn* conn = pair.second;
      
      if (!conn) continue; // Skip null connections
      
      struct pollfd pfd = {fd, 0, 0};
      
      // Set poll events based on connection state
      if (conn->want_read) pfd.events |= POLLIN;
      if (conn->want_write) pfd.events |= POLLOUT;
      
      // Always check for errors
      pfd.events |= POLLERR;
      
      poll_fds.push_back(pfd);
    }

    // Wait for events
    int ready = poll(poll_fds.data(), poll_fds.size(), -1);
    if (ready < 0) {
      if (errno == EINTR) continue; // Interrupted, retry
      std::cerr << "poll() error: " << strerror(errno) << std::endl;
      break;
    }

    // Check server socket
    if (poll_fds[0].revents & POLLIN) {
      Conn* new_conn = accept_client(server_fd);
      if (new_conn) {
        fd_to_conn[new_conn->fd] = new_conn;
      }
    }

    // Check client connections (start from index 1 to skip server socket)
    for (size_t i = 1; i < poll_fds.size(); i++) {
      struct pollfd& pfd = poll_fds[i];
      if (pfd.revents == 0) continue; // No events for this fd
      
      // Find the corresponding connection
      auto it = fd_to_conn.find(pfd.fd);
      if (it == fd_to_conn.end()) {
        continue; // Connection not found
      }
      
      Conn* conn = it->second;
      if (!conn) {
        fd_to_conn.erase(it);
        continue; // Skip null connection
      }
      
      // Handle readable socket
      if (pfd.revents & POLLIN) {
        handle_read(conn);
      }
      
      // Handle writable socket
      if (pfd.revents & POLLOUT) {
        handle_write(conn);
      }
      
      // Handle errors or close request
      if ((pfd.revents & POLLERR) || conn->want_close) {
        // Close the connection
        close(pfd.fd);
        delete conn;
        fd_to_conn.erase(pfd.fd);
      }
    }
  }
  
  // Clean up
  for (auto& pair : fd_to_conn) {
    close(pair.second->fd);
    delete pair.second;
  }
  
  close(server_fd);
  return 0;
}