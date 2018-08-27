netmap_mqpipe: netmap_mqpipe.c
	gcc -Wall -Wno-format-truncation -g netmap_mqpipe.c -o netmap_mqpipe

clean:
	rm netmap_mqpipe
