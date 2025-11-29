CXX ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -pedantic -std=c++17

LDFLAGS_SERVER ?= -lssl -lcrypto -lsqlite3
LDFLAGS_CLIENT ?= -lssl -lcrypto

SERVER = server
CLIENT = client

all: $(SERVER) $(CLIENT)

$(SERVER): server-side.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS_SERVER)

$(CLIENT): client-side.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS_CLIENT)

clean:
	rm -f $(SERVER) $(CLIENT) *.o

.PHONY: all clean
