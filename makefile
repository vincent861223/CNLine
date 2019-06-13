CC = gcc
FLAGS = -Wall

all: server client

server: server.c
	$(CC) $< -o $@ $(FLAGS)

client: client.c
	$(CC) $< -o $@ $(FLAGS) -pthread

clean:
	rm -f server client
