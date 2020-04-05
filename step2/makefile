
TRACERSC	=	src/tracer.c			\
			src/step1.c			\
			src/step2.c

TRACEEC		=	src/tracee.c



all : tracer tracee

tracer : $(TRACERSC)
	gcc -o tracer -Wall -Wextra $(TRACERSC) -Iinclude

tracee : $(TRACEEC)
	gcc -o tracee -Wall -Wextra $(TRACEEC) -Iinclude

clean:
	rm tracee tracer
