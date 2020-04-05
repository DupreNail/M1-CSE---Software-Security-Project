#include <stdio.h>
#include <unistd.h>

static int globalTracee = 0;

/**
   This function will be constantly called by our tracee, this is where our code injection will happen.
 **/
static void f1(){
  printf("In F1, PRINT! %d\n", globalTracee);
  globalTracee += 1;
  return;
}
/**
   This function will be called through step3 in our tracee
   It is otherwise unused, and is signaled as such when we compile with -Weverytinhg
   Which is why we have specified the __attribute__((used)) to our function
 **/
__attribute__((used)) static int f2(int i){
  i += 100;
  printf("In F2, value of return is %d\n", i);
  return (i);
}

int main(void) {
  int numberOfLoop = 0;
  while (numberOfLoop != 100000) {
    f1();
    sleep(1);
  }
  return (1);
}
