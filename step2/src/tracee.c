#include <stdio.h>
#include <unistd.h>

void f1(int test){
  printf("PRINT! %d\n", test);
  return;
}

int main(void) {
  
  void  *f1_ptr; //declaration of pointer to the function
  f1_ptr = &f1;
  
  printf(" Address of function = [%p]",  f1_ptr);
  fflush(0);
  int test = 0;
  
  while (1) {
    f1(test++);
    sleep(1);
  }
  return (1);
}
