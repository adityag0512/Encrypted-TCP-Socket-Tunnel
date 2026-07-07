CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread
LDFLAGS  = -lssl -lcrypto -lpthread


.PHONY: all clean server client


all: server client
	@echo ""
	@echo " Build complete!"
	@echo "  Run server: ./server/server <port> <key>"
	@echo "  Run client: ./client/client <server-ip> <port> <key>"
	@echo "  Example:    ./server/server 9000 mykey123"
	@echo "              ./client/client 127.0.0.1 9000 mykey123"

server: server/server.cpp common/logger.hpp common/protocol.hpp \
        common/crypto.hpp common/socket_utils.hpp
	@echo "Compiling server..."
	$(CXX) $(CXXFLAGS) -o server/server server/server.cpp $(LDFLAGS)
	@echo " server/server built"

client: client/client.cpp common/logger.hpp common/protocol.hpp \
        common/crypto.hpp common/socket_utils.hpp
	@echo "Compiling client..."
	$(CXX) $(CXXFLAGS) -o client/client client/client.cpp $(LDFLAGS)
	@echo " client/client built"

clean:
	rm -f server/server client/client
	@echo " Cleaned build artifacts"