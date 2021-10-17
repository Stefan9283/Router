PROJECT=router
CSOURCES=skel.c #queue.c list.c 
LIBRARY=nope
INCPATHS=include
LIBPATHS=.
LDFLAGS=
CFLAGS=-c -Wall -g
CC=gcc

# Automatic generation of some important lists
INCFLAGS=-I$(INCPATHS)
LIBFLAGS=$(LIBPATHS)

# Set up the output file names for the different output types
BINARY=$(PROJECT)

$(BINARY): $(OBJECTS)
	$(CC) $(INCFLAGS) $(CFLAGS) -fPIC skel.c -o skel.o
	$(CC) $(INCFLAGS) $(CFLAGS) router.cpp
	$(CC) skel.o router.o -lm -lstdc++ -o router

distclean: clean
	rm -f $(BINARY)

clean:
	rm -f $(OBJECTS) router.o router

pack:
	zip -r Toma_Stefan-Madalin_323CC.zip include README router.cpp  skel.c Makefile