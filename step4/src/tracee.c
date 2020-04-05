#include <stdio.h>
#include <unistd.h>

int test = 0;

void f1(){
  test += 1;
  printf("PRINT! %d\n", test);
  return;
}

int f2(int i){
  printf("PAGESIZE:%d\n",getpagesize());
  //i += 100;
  printf("In F2, value of parameter is %d", i);
  return (i);
}

int main(void) {
  
  void  *f1_ptr; //declaration of pointer to the function
  f1_ptr = &f1;
  
  printf(" Address of function = [%p] || pagesize:%d \n",  f1_ptr, getpagesize());
  fflush(0);
  while (1) {
    f1();
    sleep(1);
  }
  return (1);
}
