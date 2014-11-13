
IDASDK = /d/idasdk66
IDATARGET=joker.plw
OBJS = joker4ida.o
CC = g++
INC = -I$(IDASDK)/include

# The suggest CFLGAS should be :
# -DWIN32 -D__NT__ -D__IDP__ -mrtd
# but mrtd will cause link failed (get_segm_by_name for example) on IDASDK6.6
# g++ use CFLAGS used for *.c file extension, and CXXFLAGS for *.cpp
CFLAGS = -DWIN32 -D__NT__ -D__IDP__ -Wno-write-strings $(INC)
LDFLAGS = --static -Wl,--dll -shared
LIBS = $(IDASDK)/lib/x86_win_gcc_32/ida.a

all:$(IDATARGET)

joker:
	gcc -Wall utils.c joker.c -o joker

$(IDATARGET):$(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS) $(LDFLAGS)
	
install:
	cp -af $(IDATARGET) "/c/Program Files/IDA 6.6/plugins"

clean:
	rm joker.exe $(IDATARGET) *.o