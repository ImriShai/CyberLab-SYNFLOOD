CC = gcc
CFL = -Wall -g

.PHONY: all clean cleanall

all: Attack

Attack: Attack.o
	$(CC) $(CFL) -lpcap -lnet -o $@ $^

Attack.o: Attack.c
	$(CC) $(CFL) -c $<


clean:
	rm -f *.o Attack

cleanall:
	rm -f *.o Attack *.txt *.png
