server : dnsserver.c
	gcc dnsserver.c -o server -lpthread
	./server 53000
