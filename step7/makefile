
TRACERSC        =       src/tracer.c                    \
                        src/step1.c			\
                        src/ptrace_utils.c              \
                        src/step2.c                     \
                        src/step3.c                     \
                        src/step4.c                     \
                        src/step5.c                     \
                        src/step6.c                     \
                        src/step7.c

TRACEEC         =       src/tracee.c



all : gcc

gcc : tracergcc traceegcc

clang :	tracerclang traceeclang

debug : traceegcc tracerDebug

undefined: traceeclang tracerUndefined

tracergcc : $(TRACERSC)
	gcc  -fpie -pie -Wall -Wextra -o tracer $(TRACERSC) -Iinclude

traceegcc : $(TRACEEC)
	gcc  -fpie -pie -Wall -Wextra -o tracee $(TRACEEC) -Iinclude

tracerclang: $(TRACERSC)
	clang -Weverything -fpie -pie -O0 -Wall -Wextra -o tracer $(TRACERSC) -Iinclude

traceeclang: $(TRACEEC)
	clang  -Weverything -fpie -pie -O1 -Wall -Wextra -o tracee $(TRACEEC) -Iinclude

tracerDebug: $(TRACERSC)
	gcc -fpie -pie -Wall -Wextra -D'DEBUG_MODE' -o tracer $(TRACERSC) -Iinclude

tracerUndefined:$(TRACERSC)
	clang -D'DEBUG_MODE' -fsanitize=undefined -fpie -pie -O2 -o tracer $(TRACERSC) -Iinclude

clean:
	rm -f tracee tracer

re: clean all
