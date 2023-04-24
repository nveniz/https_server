all: ucy_https

ucy_https: httpsServer.c requestQueue.c handleMessages.c errorHandling.c
	cc -ggdb -o ucy_https httpsServer.c requestQueue.c handleMessages.c errorHandling.c -lpthread -lc -lssl -lcrypto

clean:
	rm -rf ucy_https
