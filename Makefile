all: ucy_https

ucy_https: httpsServer.c requestQueue.c handleMessages.c
	cc -o ucy_https httpsServer.c requestQueue.c handleMessages.c -lc -lssl -lcrypto

clean:
	rm -rf ucy_https
