#include <string.h>
#include <stdlib.h>
#include "headers.h"

/**
   Get the offset of a function
   @param fp , a file descriptor used to get the resul of our command
          buffer, used to get that return
          command, used to stock the command to execute
          execName, the name of the target executable 
          functionName, the name of the target function
          functionAddr, a string which will contain the resul
   @return the offset of a function of name functionNAme contained inside an executable of name execName
 **/
static char *getFunctionAddr(FILE *fp, char *buffer, char *command, char* execName, char *functionName, char *functionAddr) {
  sprintf(command, "nm %s", execName); //command point to chars which represent nm executableName
  fp = popen(command, "r");            //We "execute" the command, the result is stored inside fp
  if (fp == NULL) {                   
    perror("getFunctionAddr: FOPEN");  //If the open failed, we show an error message and exit
    exit(EXIT_FAILURE);
  }
  while	(fgets(buffer, MALLOC_SIZE, fp) != NULL) { //we read from the file descriptor until ...
    if (strstr(buffer, functionName) != NULL) {    //we find a line containing our functionName
      functionAddr = strtok(buffer, " ");          //we "get" the offset of the function,
      break;                                       //store it inside functionAddr.
    }
  }
  pclose (fp);
  DEBUG_STRING("Return", functionAddr);
  return (functionAddr);
}

/**
 Get the PID of our the executable which name is given with execName
 return nothing, but our buffer will contains the pid of our executable
 @param fp , a file descriptor which will be used to get the result of the command pgrep execname
        buffer, used to get that return
        command, used to stock the command to execute
        execName, containing the name of the executable to look for
 **/
static void getPID(FILE *fp, char *buffer, char *command, char *execName) {
  sprintf(command, "pgrep %s",execName); //command point to chars which represent pgrep executableName
  fp = popen(command, "r");              //We "execute" the command, the result is stored inside fp
  free(command);
  if (fp == NULL) {
    perror("getPID: FOPEN");
    exit(EXIT_FAILURE);
  }
  fgets(buffer, MALLOC_SIZE, fp);       //we "get" the pid of the executable, store it inside buffer
  pclose(fp);
}

/**
   This function will look inside proc/pid/maps in order to find the range of address where 
   our function is, then compute it to return the address of our function
   @param  pid , the pid of tje executable we wish to compute the address of. Must be the same as the one returned by getPID
           command, used to stock the command to execute
           fp,fp, a file descriptor which will be used to get the result of the command cat /proc/pid/maps
           buffer, used to stock the result of our commabd
           functionAddr, representing the offset that we got from the call to getFunctionAddr
   @return long addr, containing the address of a function found in the executable with PID pid
 **/
 static long getAddrFunc(char *pid, char *command, FILE *fp, char *buffer, char *functionAddr) {
   long addr = 0;
   pid[strlen(pid) - 1] = pid[strlen(pid)];
   sprintf(command, "cat /proc/%s/maps",pid);     //command point to chars which represent cat /proc/pidOfTracee/maps
   fp = popen(command, "r");                      //We "execute" the command, the result is stored inside fp
   if (fp == NULL) {
     perror("getAddrFunc: FOPEN");
     exit(EXIT_FAILURE);
   }

   while (fgets(buffer, MALLOC_SIZE, fp) != NULL) { //we read from the file descriptor until ...                                                                                                          
     if ((strstr(buffer, "r--p") != NULL) &&(strstr(buffer, "tracee") != NULL)) {          //we find a line containing the adequate execution rights 
       char *tokResult = strtok(buffer, " ");         //We get the range of addresses ...                                                                                                                  
       char * firstAddr = strtok(tokResult, "-");     //And we only keep the first one                                                                                            
       addr = (long)strtoul(firstAddr, NULL, 16);           //we then add the address that we got from getFunctionAddr                                                   
       addr += strtoul(functionAddr,NULL, 16);        //to the address that we just got, then return the result
       break;
     }
   }
   pclose(fp);
   return(addr);
 }


/**
   This Functions return a long containing the Address of a function that is present 
   inside a program currently executing. 
   @param  execName is the executable name in which the search will be done, for example tracee
           functionName is the name of the function that we are looking for, for example f1 or f2
   @return A long containing the address of ourfunction. our PID is also set so that it contains
           the pid is also set, it contains the pid of the executable, for example tracee
 **/
long step1(char *execName, char *functionName, char **pid) {
  
  FILE *fp;
  char *temp;
  char *buffer;
  char *command;
  char *functionAddr;
  long traceeFuncAddr;
  
  fp = NULL;
  functionAddr = NULL;

  
  buffer = malloc(sizeof(char) * MALLOC_SIZE);                                                 //buffer will be used to store what is read from fp
  command = malloc(sizeof(char) * (strlen(execName) + strlen("nm ") + 1));                     //command will "store" the different command that we will use
  functionAddr = getFunctionAddr(fp, buffer, command, execName, functionName, functionAddr);   //functionAddr store the offset the address of the function found with nm
  temp = malloc(sizeof(char) * strlen(functionAddr) + 1);                                      //temp is used to make sure that strtok does not modify our functionAddr
  strcpy(temp, functionAddr);

  free(command);
  command = malloc(sizeof(char) * (strlen(execName) + strlen("pgrep ") + 1));                  //we free then malloc everytime we change our command, to make sure our size is the right one
  getPID(fp, buffer, command, execName);                                                       //We get the pid of our tracee 
  *pid = strdup(buffer);                                                                       //strdup once again to make sure that strtok will not impact our result
  command = malloc(sizeof(char) * (strlen("cat /proc//maps") + strlen(*pid) + 1));
  traceeFuncAddr = getAddrFunc(*pid, command, fp, buffer, temp);                               //We compute the address of f1 functionName (f1) in execName(tracee)
  free(command);
  free(functionAddr);
  free(temp);
  DEBUG_LONG("Retrun of step 1", traceeFuncAddr);
  return (traceeFuncAddr);
}
