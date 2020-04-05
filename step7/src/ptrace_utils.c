#include "headers.h"
#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/wait.h>

/**
a function that will attach our program to another, and wait for the "confirmation" that it was attach
@param pid , representing the PID of the program we wish to attach to
 **/
void attachAndWait(const int pid) {
  if (ptrace(PTRACE_ATTACH, pid, 0,0) < 0){            //We try to attach to our pid, which is the pid of the tracee
    perror("attachAndWait: ptrace_attach");            //If our ATTACH fail, we show an error message and exit
    exit(EXIT_FAILURE);
  }
  if (waitpid(pid, NULL, 0) != pid){                   //we wait for the tracee to stop, so that we do not try to read or write anything from/to it will it is not fully stoped
    perror("attachAndWait: waitpid");
    exit(EXIT_FAILURE);
  }
}


/**
A function that will send a cont signal to another program, and wait for the "return signal"
@param pid , representing the PID of the program we wish to send the program to
 **/
void contAndWait(const int pid) {
  if (ptrace(PTRACE_CONT, pid, NULL,NULL) < 0) {       //We send a cont signal to our pid, which is the pid of the tracee
    perror("contAndWait: ptrace_cont");                //if our cont fail, we show and error and exit
    exit(EXIT_FAILURE);
  }
  if (waitpid(pid, NULL,0) != pid){                    //jsut like attachAndWait, we wait for the tracee to "confirm" it has received our signal
    perror("contAndWait: waitpid");
    exit(EXIT_FAILURE);
  }

}
