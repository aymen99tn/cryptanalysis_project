CXX ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -pedantic -std=c++17
LDFLAGS ?= -lssl -lcrypto -lsqlite3

SERVER = server

all: $(SERVER)

$(SERVER): server-side.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(SERVER) *.o

.PHONY: all clean
