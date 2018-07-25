/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.2.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */
#include "qemu/osdep.h"
#include "cpu.h"

#include <sys/shm.h>
#include "afl.h"
#include "../../config.h"
#include <time.h>

char *current_data = NULL;
char *orig_data = NULL;
int print_start = 0;
int print_index = 0;
int print_pc[1000];
//zyw
static u_long bufsz;
static char *buf; //zyw
static u_int64_t *arr;
#define SZ 4096

/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* A snippet patched into tb_find_slow to inform the parent process that
   we have hit a new block that hasn't been translated yet, and to tell
   it to translate within its own context, too (this avoids translation
   overhead in the next forked-off copy). */
/*
#define AFL_QEMU_CPU_SNIPPET1 do { \
    afl_request_tsl(pc, cs_base, flags); \
  } while (0)
*/

#define AFL_QEMU_CPU_SNIPPET1 do { \
    afl_request_tsl(cpu, last_tb, tb_exit); \
  } while (0)

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

/*
#define AFL_QEMU_CPU_SNIPPET2(env, pc) do { \
    if(pc == afl_entry_point && pc && getenv("AFLGETWORK") == 0) { \
      afl_setup(); \
      afl_forkserver(env); \
      aflStart = 1; \
    } \
    afl_maybe_log(pc); \
  } while (0)
*/

#define AFL_QEMU_CPU_SNIPPET2(env, pc) do { \
    afl_maybe_log(pc); \
  } while (0)

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

/* This is equivalent to afl-as.h: */

static unsigned char *afl_area_ptr = 0;

/* Exported variables populated by the code patched into elfload.c: */

target_ulong afl_entry_point = 0, /* ELF entry point (_start) */
          afl_start_code = 0,  /* .text start pointer      */
          afl_end_code = 0;    /* .text end pointer        */

int aflStart = 0;               /* we've started fuzzing */
int aflEnableTicks = 0;         /* re-enable ticks for each test */
int aflGotLog = 0;              /* we've seen dmesg logging */

/* from command line options */
//const char *aflFile = "/tmp/work"; //zyw
extern const char * aflFile; //zyw

unsigned long aflPanicAddr = (unsigned long)-1;
unsigned long aflDmesgAddr = (unsigned long)-1;

/* Set in the child process in forkserver mode: */

unsigned char afl_fork_child = 0;
//int afl_wants_cpu_to_stop = 0; //zyw
extern int afl_wants_cpu_to_stop; //zyw
unsigned int afl_forksrv_pid;

/* Instrumentation ratio: */

static unsigned int afl_inst_rms = MAP_SIZE;

/* Function declarations. */

static inline void afl_maybe_log(target_ulong);

static void afl_wait_tsl(CPUArchState*, int);
//static void afl_request_tsl(target_ulong, target_ulong, uint64_t);
static void afl_request_tsl(CPUState *, TranslationBlock *, int);
//zyw
/*
static TranslationBlock *tb_find_slow(CPUArchState*, target_ulong,
                                      target_ulong, uint64_t);
*/
/*
static TranslationBlock *tb_find_slow(CPUState*, TranlationBlock *,
                                      int );
*/

TranslationBlock *afl_tb_find(CPUState *cpu,
                                        TranslationBlock *last_tb,
                                        int tb_exit);


/* Data structure passed around by the translate handlers: */
/*
struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint64_t flags;
};
*/

struct afl_tsl {
  CPUState * cpu;
  TranslationBlock *last_tb;
  int tb_exit;
};


	
//zyw
extern int kernel_stack_count;
extern int user_stack_count;
extern int kernel_origpt;
extern int user_origpt;
extern int user_forkpt;
extern int user_stack[1000];
//extern int kenerl[0x10000000];

extern target_ulong startCreatesnapshot(CPUArchState *env, target_ulong enableTicks);
extern target_ulong endWork(target_ulong status);
extern target_ulong startFork(CPUArchState *env, target_ulong enableTicks);
extern void loadCPUState(CPUArchState *env);
extern void storeCPUState(CPUArchState *env);

#define MAX_STACK_SIZE 5000
uint32_t sys_call_ret_stack[2][MAX_STACK_SIZE];
uint32_t sys_call_entry_stack[2][MAX_STACK_SIZE];
uint32_t cr3_stack[2][MAX_STACK_SIZE];
uint32_t stack_top[2];

uint32_t saved_stack[2][MAX_STACK_SIZE];
uint32_t saved_stack_top[2];

void backup_stack()
{
	for(int index=0; index<2; index++)
	{
		for(int i=0; i<stack_top[index]; i++)
		{	
			saved_stack[index][i] = sys_call_entry_stack[index][i];
		}
		saved_stack_top[index] = stack_top[index];
	}
}

void restore_stack()
{
	for(int index=0; index<2; index++)
	{
		for(int i=0; i<saved_stack_top[index]; i++)
		{	
			sys_call_entry_stack[index][i] = saved_stack[index][i] ;
		}
		stack_top[index] = saved_stack_top[index];
	}
}



/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Set up SHM region and initialize other stuff. */

void afl_setup(void) {

  char *id_str = getenv(SHM_ENV_VAR),
       *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;

  }

  if (id_str) {

    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);
    
    if (afl_area_ptr == (void*)-1) exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;


  }

  if (getenv("AFL_INST_LIBS")) {

    afl_start_code = 0;
    afl_end_code   = (target_ulong)-1;

  }
}

static ssize_t uninterrupted_read(int fd, void *buf, size_t cnt)
{
    ssize_t n;
    while((n = read(fd, buf, cnt)) == -1 && errno == EINTR)
        continue;
    return n;
}

/* Fork server logic, invoked once we hit _start. */
static struct timeval tv_time;

extern void afl_wait_tlb(int fd);

int forkserver_looptimes = 0;

void afl_forkserver(CPUArchState *env) {
//zyw
  MIPSCPU *mips_cpu = mips_env_get_cpu(env);
  CPUState *cpu = CPU(mips_cpu);

//zyw

  static unsigned char tmp[4];
  if (!afl_area_ptr) return;
  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {
    
    forkserver_looptimes ++;
    if(forkserver_looptimes == 2) sleep(10000);
    pid_t child_pid;
    int status, t_fd[2];

    /* Whoops, parent dead? */
	
    if (uninterrupted_read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    /* Establish a channel with child to grab translation commands. We'll 
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);
    struct timeval tv_start;
    gettimeofday(&tv_start,NULL);
    DECAF_printf("before fork process\n");


    user_forkpt = env->active_tc.gpr[29];//sp
    //DECAF_printf("save state restart_cpu:%x,pc:%x, user_forkpt:%x, user_stack:%x, len:%d\n",cpu,env->active_tc.PC, user_forkpt, user_stack, user_origpt-user_forkpt);
    if(user_origpt-user_forkpt > 0){
	    cpu_memory_rw_debug(cpu, user_forkpt, user_stack, user_origpt-user_forkpt, 0);
/*
	    DECAF_printf("save state");
	    for(int i=0;i<1000;i++)
	      {  
		if(user_stack[i]!=0){
			DECAF_printf("%x ",user_stack[i]);
		}
	     }DECAF_printf("\n");
*/
    }


    child_pid = fork();
    
    if (child_pid < 0) exit(4);

    if (!child_pid) {
      //DECAF_printf("restart_cpu:%x, pc:%x, sp:%x, user_forkpt:%x, user_stack:%x, len:%d\n",cpu, env->active_tc.PC, env->active_tc.gpr[29], user_forkpt, user_stack, user_origpt-user_forkpt);
      
      //if(cpu_memory_rw_debug(cpu, user_forkpt, user_stack, user_origpt-user_forkpt, 1)!=0) DECAF_printf("memory write error\n");
      DECAF_printf("in child process\n");
      struct timeval tv_end;
      gettimeofday(&tv_end,NULL);
      ////DECAF_printf("fork time is %f\n", (tv_end.tv_sec - tv_start.tv_sec) + ((float)(tv_end.tv_usec - tv_start.tv_usec))/1000000);
     //// DECAF_printf("start time,%d,%d\n", tv_end.tv_sec, tv_end.tv_usec);
      /* Child process. Close descriptors and run free. */

      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      return;

    }

    /* Parent. */
	
    close(TSL_FD);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    //afl_wait_tsl(env, t_fd[0]);
    afl_wait_tlb(t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  }

}

static inline target_ulong aflHash(target_ulong cur_loc)
{
  if(!aflStart)
    return 0;

  if(!print_start)
    return 0;
  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */

  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
    return 0;

  //DECAF_printf("exec %lx\n", cur_loc); //zyw
  //if(print_start ==1){
  	//DECAF_printf("exec %lx\n", cur_loc); //zyw path information
	//print_pc[print_index] = cur_loc;
	//print_index++;
  //}
#ifdef DEBUG_EDGES
  if(1) {
    printf("exec %lx\n", cur_loc);
    fflush(stdout);
  }
#endif

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  target_ulong h = cur_loc;
#if TARGET_LONG_BITS == 32
  h ^= cur_loc >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
#else
  h ^= cur_loc >> 33;
  h *= 0xff51afd7ed558ccd;
  h ^= h >> 33;
  h *= 0xc4ceb9fe1a85ec53;
  h ^= h >> 33;
#endif

  h &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (h >= afl_inst_rms) return 0;
  return h;
}

/* todo: generate calls to helper_aflMaybeLog during translation */
static inline void helper_aflMaybeLog(target_ulong cur_loc) {
  static __thread target_ulong prev_loc;
  //if(print_start ==1){
  	//DECAF_printf("exec %lx\n", cur_loc); //zyw path information
	//print_pc[print_index] = cur_loc ^ prev_loc;
	//print_index++;
  //}
  afl_area_ptr[cur_loc ^ prev_loc]++;
  //DECAF_printf("loc:%x\n", cur_loc ^ prev_loc);
  prev_loc = cur_loc >> 1;
}

/* The equivalent of the tuple logging routine from afl-as.h. */

static inline void afl_maybe_log(target_ulong cur_loc) {
  cur_loc = aflHash(cur_loc);
  if(cur_loc)
    helper_aflMaybeLog(cur_loc);
}


/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

/*
static void afl_request_tsl(target_ulong pc, target_ulong cb, uint64_t flags) {

  struct afl_tsl t;

  if (!afl_fork_child) return;
  //DECAF_printf("afl_request_tsl\n");
  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}
*/

static void afl_request_tsl(CPUState* cpu, TranslationBlock *last_tb, int tb_exit)
{
  struct afl_tsl t;

  if (!afl_fork_child) return;
  t.cpu = cpu;
  t.last_tb = last_tb;
  t.tb_exit = tb_exit;
  //DECAF_printf("reqeust_tsl, %x\n", last_tb);
  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}



/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUArchState *env, int fd) {

  struct afl_tsl t;
  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;
    CPUArchState * env =  (CPUArchState *)t.cpu->env_ptr;
    int c_pc = env->active_tc.PC;
    //DECAF_printf("afl  wait tsl:%x\n", c_pc);
    if(env && 0) {
#ifdef CONFIG_USER_ONLY
        //tb_find_slow(env, t.pc, t.cs_base, t.flags);
#else
	
        /* if the child system emulator pages in new code and then JITs it, 
        and sends its address to the server, the server cannot also JIT it 
        without having it's guest's kernel page the data in !  
        so we will only JIT kernel code segment which shouldnt page.
        */
        // XXX this monstrosity must go!
        //if(t.pc >= 0xffffffff81000000 && t.pc <= 0xffffffff81ffffff) {

	//if(c_pc >= 0x81000000 && c_pc<= 0x81ffffff) {
	if(c_pc >= 0x80000000 && c_pc < 0x90000000) {
	    //DECAF_printf("afl-qemu-cpu-inl:%x,%x\n", t.last_tb, c_pc);
            //printf("wait_tsl %lx -- jit\n", t.pc); fflush(stdout);
            //tb_find_slow(env, t.pc, t.cs_base, t.flags);
	     afl_tb_find(t.cpu, t.last_tb, t.tb_exit);
        } else {
            //printf("wait_tsl %lx -- ignore nonkernel\n", t.pc); fflush(stdout);
        }

#endif
    } else {
        //printf("wait_tsl %lx -- ignore\n", t.pc); fflush(stdout);
    }

  }

  close(fd);

}


void afl_createsnapshot(CPUArchState *env, target_ulong enableTicks)
{

	static unsigned char tmp[4];
	//DECAF_printf("forkserver:%d\n", afl_area_ptr);
	if (!afl_area_ptr) return;
	/* Tell the parent that we're alive. If the parent doesn't want
	to talk, assume that we're not running in forkserver mode. */

	if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

	/* All right, let's await orders... */
	if (uninterrupted_read(FORKSRV_FD, tmp, 4) != 4) exit(2);

// save snapshot
	Error *err = NULL;
	const char *snapshot_name = "decaf_snap";
	save_snapshot(snapshot_name, &err);
	backup_stack();
//
	//hmp_handle_error(cur_mon, &err);
	
	print_start = 1;

	afl_forksrv_pid = getpid() + 1;
	if (write(FORKSRV_FD + 1, &afl_forksrv_pid, 4) != 4) exit(5);

	DECAF_printf("afl create snapshot\n");


	return 0;
}






static target_ulong startForkserver(CPUArchState *env, target_ulong enableTicks)
{
    //printf("pid %d: startForkServer\n", getpid()); fflush(stdout);
    assert(!afl_fork_child);
#ifdef CONFIG_USER_ONLY
    /* we're running in the main thread, get right to it! */
    afl_setup();
    afl_forkserver(env);
#else
    /*
     * we're running in a cpu thread. we'll exit the cpu thread
     * and notify the iothread.  The iothread will run the forkserver
     * and in the child will restart the cpu thread which will continue
     * execution.
     * N.B. We assume a single cpu here!
     */
    //DECAF_printf("config_system\n");
    aflEnableTicks = enableTicks; //zyw
    afl_wants_cpu_to_stop = 1;
    print_start = 1;
   
#endif
    return 0;
}

/* copy work into ptr[0..sz].  Assumes memory range is locked. */
static target_ulong getWork(CPUArchState *env, char * ptr, target_ulong sz)
{
    target_ulong retsz;
    FILE *fp;
    unsigned char ch;
    //printf("pid %d: getWork %lx %lx\n", getpid(), ptr, sz);fflush(stdout);
    //assert(aflStart == 0);
    DECAF_printf("filename:%s\n",aflFile);
    fp = fopen(aflFile, "rb");
    if(!fp) {
         perror(aflFile);
	 DECAF_printf("aflFile open failed\n");
         return errno;
    }
    retsz = 0;
    while(retsz < sz) {
        if(fread(&ch, 1, 1, fp) == 0)
            break;
        //cpu_stb_data(env, ptr, ch);
	//DECAF_printf("ch:%c\n",ch);
	*ptr = ch;
        retsz ++;
        ptr ++;
    }
    fclose(fp);
    return retsz;
}

static target_ulong readFile(char * filename, char *ptr, target_ulong sz)
{
    target_ulong retsz;
    FILE *fp;
    unsigned char ch;
    fp = fopen(filename, "rb");
    if(!fp) {
	 DECAF_printf("aflFile open failed\n");
         return errno;
    }
    retsz = 0;
    while(retsz < sz) {
        if(fread(&ch, 1, 1, fp) == 0)
            break;

	*ptr = ch;
        retsz ++;
        ptr ++;
    }
    fclose(fp);
    return retsz;
}

/*
static target_ulong startWork(CPUArchState *env, target_ulong ptr)
{
    target_ulong start, end;

    //printf("pid %d: ptr %lx\n", getpid(), ptr);fflush(stdout);
    start = cpu_ldq_data(env, ptr);
    end = cpu_ldq_data(env, ptr + sizeof start);
    //printf("pid %d: startWork %lx - %lx\n", getpid(), start, end);fflush(stdout);

    afl_start_code = start;
    afl_end_code   = end;
    aflGotLog = 0;
    aflStart = 1;
    return 0;
}
*/

static target_ulong startTrace(CPUArchState *env, target_ulong start, target_ulong end)
{
    afl_start_code = start;
    afl_end_code   = end;
    aflGotLog = 0;
    aflStart = 1;
    return 0;
}

static target_ulong stopTrace()
{
    afl_start_code = 0;
    afl_end_code   = 0;
    aflGotLog = 0;
    aflStart = 0;
    return 0;
}

static target_ulong doneWork(target_ulong val)
{
    //printf("pid %d: doneWork %lx\n", getpid(), val);fflush(stdout);
    //assert(aflStart == 1);
/* detecting logging as crashes hasnt been helpful and
   has occasionally been a problem.  We'll leave it to
   a post-analysis phase to look over dmesg output for
   our corpus.
 */
#ifdef LETSNOT 
    if(aflGotLog)
        exit(64 | val);
#endif
    exit(val); /* exit forkserver child */
}

static struct timeval snap_time;

target_ulong afl_endWork(int saved_vm_running, int stat)
{
// need reload vmi, reset afl data.
    DECAF_printf("afl_endWork\n");
    int status = 0; //?WEXITSTATUS;
    static unsigned char tmp[4];
    status = stat;
//exit
/*
    int pid = fork();
    if(pid == 0) exit(0);
    waitpid(pid, &status, 0);
    printf("status is %x\n", status);
*/


//write status crash or not?
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);
//restart from parent
    if (uninterrupted_read(FORKSRV_FD, tmp, 4) != 4) exit(2);
    
    const char *name = "decaf_snap";
    Error *err = NULL;

//reset afl_area_ptr, afl_start
    //memset(afl_area_ptr, 0, sizeof(afl_area_ptr) -1 );
    //DECAF_printf("size of unsigned char:%d\n", sizeof(unsigned char));
    memset(afl_area_ptr, 0, 0xfffff*sizeof(unsigned char));
//
    print_start = 1;
  
// load_snapshot 
    gettimeofday(&snap_time, NULL);
    DECAF_printf("before load time:%d,%d\n", snap_time.tv_sec, snap_time.tv_usec);
    stopTrace();
    restore_stack();
    if (load_snapshot(name, &err) == 0 && saved_vm_running) {
	gettimeofday(&snap_time, NULL);
	DECAF_printf("after load time:%d,%d\n", snap_time.tv_sec, snap_time.tv_usec);
        vm_start();
    }
 
    //hmp_handle_error(cur_mon, &err);
//

    //DECAF_printf("startCreatesnapshot9 over\n");
    afl_forksrv_pid = getpid() + 1;
    if (write(FORKSRV_FD + 1, &afl_forksrv_pid, 4) != 4) exit(5);
    DECAF_printf("\n\nafl reload snapshot\n");
    return 0;
}

u_long aflInit(char *pt)
{
    static int aflInit = 0;
    char *pg;
/*
    if(aflInit)
        return 0;
*/
    //pg = mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    pg = (char *)malloc(4096);
    if(pg == (void*)-1) {
        perror("mmap");
        exit(1);
    }
    memset(pg, 0, SZ); // touch all the bits!

/*
    arr = (u_int64_t *)pg;
    buf = pg + 2 * sizeof arr[0];
    bufsz = SZ - 2 * sizeof arr[0];
    pt = buf;
*/
    pt = pg;
    bufsz = SZ;
    aflInit = 1;
    return SZ;
}

static void watcher(void) {
    int pid, status;

    if((pid = fork()) == 0)
        return;

    waitpid(pid, &status, 0);
    /* if we got here the driver died */
    doneWork(0);
    exit(0);
}


