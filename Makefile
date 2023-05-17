all: httpsServer

httpsServer: myzhibei_http.c
	gcc -W -Wall -o httpsServer myzhibei_https_server.c -lpthread -lssl -lcrypto

clean:
	rm httpsServer
