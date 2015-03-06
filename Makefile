all: sender receiver router

sender: sender.c func_util.c
		gcc -g -w sender.c func_util.c -lpcap -lpthread -o sender	

receiver: receiver.c func_util.c
		gcc -g -w receiver.c func_util.c -lpcap -lpthread -o receiver

router: router.c routing.c func_util.c
		gcc -g -w router.c routing.c func_util.c -lpcap -lpthread -o router
	
clean:
		rm -rf sender receiver router
