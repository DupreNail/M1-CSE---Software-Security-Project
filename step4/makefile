
TRACERSC	=	src/tracer.c			\
			src/step1.c			\
			src/step2.c			\
			src/step3.c			\
			src/step4.c

TRACEEC		=	src/tracee.c



all : tracer tracee

tracer : $(TRACERSC)
	gcc -o tracer $(TRACERSC) -Iinclude

tracee : $(TRACEEC)
	gcc -o tracee $(TRACEEC) -Iinclude

clean:
	rm tracee tracer
