#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "headers.h"

int main(int argc, char **argv) {
  if (argc != 3){
    return -1;
  }

  step1(argv);
  /*
  FILE *fp;
  char nm[128];
  char *nmCommand = malloc(sizeof(char) * (strlen(argv[1] + strlen("nm "))));

  char *functionaddr;
  strcpy(nmCommand, "nm ");
  strcat(nmCommand, argv[1]);
  fp = popen(nmCommand, "r");
  free(nmCommand);
  if (fp == NULL) {
    printf("Failed to run command\n" );
    return (-1);
  }
  while (fgets(nm, sizeof(nm), fp) != NULL) {
    if(strstr(nm, argv[2]) != NULL) {
      functionaddr = strtok(nm, " ");
      break;
    }
  }
  pclose(fp);

  
  char * pgrep = malloc(sizeof(char) * (strlen(argv[1] + strlen("pgrep "))));
  strcpy(pgrep, "pgrep ");
  strcat(pgrep, argv[1]);
  fp = popen(pgrep, "r");
  free(pgrep);
  if (fp == NULL) {
    printf("Failed to run command\n" );
    return (-1);
  }
  char pid[64];
  fgets(pid, sizeof(pid), fp);
  pclose(fp);

  char * catCommand = malloc(sizeof(char) * (strlen("cat /proc//maps") + strlen(pid)));
  strcpy(catCommand, "cat /proc/");
  char * pidTemp= strdup(pid);
  pidTemp[strlen(pidTemp) - 1] = pidTemp[strlen(pidTemp)];
  strcat(catCommand,pidTemp);
  strcat(catCommand, "/maps");

  fp = popen(catCommand, "r");
  free(catCommand);
  if (fp == NULL) {
    printf("Failed to run command\n" );
    return (-1);
  }
  char cat[128];
  if( fgets(cat, sizeof(cat), fp) != NULL) {
    char *tokResult = strtok(cat, " ");
    char * temp = strtok(tokResult, "-");

    long long test = strtoul(temp, NULL, 16);
    long long firstAddr2 = strtoul(functionaddr, NULL, 16);
    printf("\nTEST: %lld, %lld, %llx   \n", test, firstAddr2, test+firstAddr2);
 
  }
  pclose(fp);
  */
}
