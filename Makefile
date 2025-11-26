CXX ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -std=c++17
LDFLAGS ?= -lssl -lcrypto

CLIENT = client

all: $(CLIENT)

$(CLIENT): client.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(CLIENT) *.o

.PHONY: all clean
