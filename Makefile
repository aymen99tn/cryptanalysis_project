CXX ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -pedantic -std=c++17
CFLAGS ?= -O2 -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION

LDFLAGS_SERVER ?= -lssl -lcrypto -ldl -lpthread
LDFLAGS_CLIENT ?= -lssl -lcrypto

SERVER = server
CLIENT = client

all: $(SERVER) $(CLIENT)

$(SERVER): server-side.o sqlite3.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS_SERVER)

$(CLIENT): client-side.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS_CLIENT)

server-side.o: server-side.cpp
	$(CXX) $(CXXFLAGS) -c $<

sqlite3.o: sqlite3.c sqlite3.h
	$(CC) $(CFLAGS) -c sqlite3.c

clean:
	rm -f $(SERVER) $(CLIENT) *.o

.PHONY: all clean
