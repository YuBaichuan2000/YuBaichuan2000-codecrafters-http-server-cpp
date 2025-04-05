#include <iostream>
#include <cstdlib>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>
#include <sstream>

std::vector<std::string> split_message(const std::string &message, const std::string& delim) {
  std::vector<std::string> tokens;
  std::stringstream ss = std::stringstream{message};
  std::string line;
  while (getline(ss, line, *delim.begin())) {
    tokens.push_back(line);
    ss.ignore(delim.length() - 1);
  }
  return tokens;
}

std::string get_path(std::string request) {
  std::vector<std::string> toks = split_message(request, "\r\n");
  std::vector<std::string> path_toks = split_message(toks[0], " ");
  return path_toks[1];
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

// Function to accept a client connection
int accept_client(int server_fd) {
  struct sockaddr_in client_addr;
  int client_addr_len = sizeof(client_addr);
  
  std::cout << "Waiting for a client to connect...\n";
  
  int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_addr_len);
  if (client_fd < 0) {
    std::cerr << "Failed to accept connection" << std::endl;
    return -1;
  }
  
  std::cout << "Client connected\n";
  return client_fd;
}

// Function to read and parse the client request
std::string handle_read(int client_fd) {
  char buffer[1024] = {0};
  
  int bytes_read = read(client_fd, buffer, sizeof(buffer)-1);
  
  if (bytes_read < 0) {
    std::cerr << "Failed to read from client" << std::endl;
    return "";
  }
  
  std::string client_msg(buffer);
  std::cout << "Received request:\n" << client_msg << std::endl;
  
  return client_msg;
}

// Function to generate a response based on the request
std::string generate_response(const std::string& client_msg) {
  std::string path = get_path(client_msg);
  std::string agent = get_agent(client_msg);
  std::vector<std::string> split_paths = split_message(path, "/");
  
  std::cout << "Received path: " << path << std::endl;
  std::cout << "Received agent: " << agent << std::endl;
  
  if (path == "/") {
    return "HTTP/1.1 200 OK\r\n\r\n";
  } else if (split_paths.size() > 1 && split_paths[1] == "echo") {
    if (split_paths.size() > 2) {
      return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " 
             + std::to_string(split_paths[2].length()) + "\r\n\r\n" + split_paths[2];
    } else {
      return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n";
    }
  } else if (split_paths.size() > 1 && split_paths[1] == "user-agent") {
    return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " 
           + std::to_string(agent.length()) + "\r\n\r\n" + agent;
  } else {
    return "HTTP/1.1 404 Not Found\r\n\r\n";
  }
}

// Function to send the response to the client
bool handle_write(int client_fd, const std::string& response) {
  int bytes_sent = write(client_fd, response.c_str(), response.length());
  if (bytes_sent < 0) {
    std::cerr << "Failed to send response\n";
    return false;
  }
  return true;
}


int main(int argc, char **argv) {
  // Flush after every std::cout / std::cerr
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;
  
  // You can use print statements as follows for debugging, they'll be visible when running tests.
  std::cout << "Logs from your program will appear here!\n";

  // TCP connection
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
   std::cerr << "Failed to create server socket\n";
   return 1;
  }
  //
  // // Since the tester restarts your program quite often, setting SO_REUSEADDR
  // // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    std::cerr << "setsockopt failed\n";
    return 1;
  }
  
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(4221);
  
  if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
    std::cerr << "Failed to bind to port 4221\n";
    return 1;
  }
  
  int connection_backlog = 5;
  if (listen(server_fd, connection_backlog) != 0) {
    std::cerr << "listen failed\n";
    return 1;
  }
  
  // Accept concurrent client connections
  while (true) {
    int client_fd = accept_client(server_fd);
    if (client_fd < 0) {
      close(server_fd);
      return 1;
    }
    
    // Read and parse client request
    std::string client_msg = handle_read(client_fd);
    if (client_msg.empty()) {
      close(client_fd);
      close(server_fd);
      return 1;
    }
    
    // Generate response
    std::string response = generate_response(client_msg);
    
    // Send response to client
    if (!handle_write(client_fd, response)) {
      close(client_fd);
      return 1;
    }
    
    // Clean up
    close(client_fd);
  }
  
  close(server_fd);
  
  return 0;
}
