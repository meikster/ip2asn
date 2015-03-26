#

CFLAGS	+=	-Wall -Werror -W -ansi -pedantic
LDFLAGS	+=	-lbsd -lgmp

NAME	=	ip2asn

SRCS	=	ip2asn.c
OBJS	=	$(SRCS:.c=.o)
CC	=	gcc

all:	$(NAME)

$(NAME):	$(OBJS)
	$(CC) -o $(NAME) $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS)
	rm -f *~
	rm -f \#*\#

fclean: clean
	rm -f $(NAME)
