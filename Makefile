CXX ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -pedantic -std=c++17
CFLAGS ?= -O2 -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION

LDFLAGS_SERVER ?= -lssl -lcrypto -ldl -lpthread
LDFLAGS_CLIENT ?= -lssl -lcrypto

SERVER = server
CLIENT = client

SRC_DIR = src

all: $(SERVER) $(CLIENT)

$(SERVER): $(SRC_DIR)/server-side.o $(SRC_DIR)/sqlite3.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS_SERVER)

$(CLIENT): $(SRC_DIR)/client-side.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS_CLIENT)

$(SRC_DIR)/server-side.o: $(SRC_DIR)/server-side.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(SRC_DIR)/sqlite3.o: $(SRC_DIR)/sqlite3.c $(SRC_DIR)/sqlite3.h
	$(CC) $(CFLAGS) -c $(SRC_DIR)/sqlite3.c -o $@

clean:
	rm -f $(SERVER) $(CLIENT) $(SRC_DIR)/*.o

.PHONY: all clean