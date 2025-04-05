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
  
  struct sockaddr_in client_addr;
  int client_addr_len = sizeof(client_addr);
  
  std::cout << "Waiting for a client to connect...\n";
  
  int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_addr_len);
  if (client_fd < 0) {
    std::cerr << "Failed to accept connection" << std::endl;
  }
  std::cout << "Client connected\n";

  // Read the HTTP request
  char buffer[1024] = {0};

  int bytes_read = read(client_fd, buffer, sizeof(buffer)-1);

  if (bytes_read < 0) {
    std::cerr << "Failed to read from client" << std::endl;
    close(client_fd);
    return 1;
  }

  std::string client_msg(buffer);

  std::cout << "Received request:\n" << client_msg << std::endl;

  std::string path = get_path(client_msg);
  std::string agent = get_agent(client_msg);
  std::vector<std::string> split_paths = split_message(path, "/");
  std::string response;

  std::cout << "Received path:\n" << path << std::endl;
  std::cout << "Received agent:\n" << agent << std::endl;

  if (path == "/") {
      response = "HTTP/1.1 200 OK\r\n\r\n";
    } else if (split_paths[1] == "echo") {
      response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + std::to_string(split_paths[2].length()) + "\r\n\r\n" + split_paths[2];
    } else if (split_paths[1] == "user-agent"){
      response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + std::to_string(agent.length()) + "\r\n\r\n" + agent;
    } else {
      response = "HTTP/1.1 404 Not Found\r\n\r\n";
    }
  

  int bytes_sent = write(client_fd, response.c_str(), response.length());
  if (bytes_sent < 0) {
    std::cerr << "Failed to send response\n";
  }

  // Clean up
  close(client_fd);

  
  close(server_fd);

  return 0;
}
