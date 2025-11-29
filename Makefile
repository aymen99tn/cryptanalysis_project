CXX ?= g++
CC ?= gcc
CXXFLAGS ?= -O2 -Wall -Wextra -pedantic -std=c++17
CFLAGS ?= -O2 -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION
LDFLAGS ?= -lssl -lcrypto -ldl -lpthread

SERVER = server
CLIENT = client

all: $(SERVER) $(CLIENT)

$(SERVER): server-side.o sqlite3.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(CLIENT): client.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

server-side.o: server-side.cpp
	$(CXX) $(CXXFLAGS) -c $<

client.o: client.cpp
	$(CXX) $(CXXFLAGS) -c $<

sqlite3.o: sqlite3.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(SERVER) $(CLIENT) *.o

.PHONY: all clean