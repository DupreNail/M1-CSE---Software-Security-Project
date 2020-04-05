#include <stdio.h>

void f1(void){
  return;
}

int main(void) {
  
  void  *f1_ptr; //declaration of pointer to the function
  f1_ptr = &f1;
  
  printf(" Address of function = [%p]",  f1_ptr);
  fflush(0);
  while (1) {
    f1();
  }
  return (1);
}
