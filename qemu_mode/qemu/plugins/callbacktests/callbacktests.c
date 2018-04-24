/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
This is a plugin of DECAF. You can redistribute and modify it
under the terms of BSD license but it is made available
WITHOUT ANY WARRANTY. See the top-level COPYING file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
/**
 * @author Lok Yan
 * @date Oct 18 2012
 */
#include "qemu/osdep.h"
#include "cpu.h"

#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "vmi_c_wrapper.h"
#include "afl-qemu-cpu-inl.h"


//http socket
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

#include <sys/time.h>

static struct timeval tv_api;
static char old_api[100];
static float sec_delta = 0.0;

//basic stub for plugins

char * VMI_find_process_name_by_pgd(uint32_t pgd);

static plugin_interface_t callbacktests_interface;
static int bVerboseTest = 0;
static int enableTimer = 0;
static int afl_begin = 0;
static int afl_fork = 0;
//static char *current_data = NULL;
static int rest_len = 0;
static int network_read_block = 0;
static int open_block = 0;
static int accept_block = 0;
static int current_fd = 0;
static int write_fd = 0;
static int start_debug = 0;
static int tmp_pc = 0;
static int httpd_pid[100]; //httpd will fork itself
static int current_pid = 0;
static char current_program[50];
static int pid_index = 0;
static target_ulong kernel_sp = 0;
static int run_test = 0;
static int http_request = 0;
static int main_start = 0;


static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle removeproc_handle = DECAF_NULL_HANDLE;
static DECAF_Handle block_begin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle block_end_handle = DECAF_NULL_HANDLE;

#define PRO_MAX_NUM 10
static char targetname[PRO_MAX_NUM][512];// 10 program, such as httpd, hedwig.cig
static uint32_t targetcr3[PRO_MAX_NUM];// 10 program, such as httpd, hedwig.cig
static uint32_t targetpid[PRO_MAX_NUM];// 10 program, such as httpd, hedwig.cig
static int target_main_address[PRO_MAX_NUM];

static int target_index = 0; //the number of target program

int target_exist(char *name){
	for(int i=0; i<target_index; i++){
		if (strcmp(targetname[i], name) == 0){
			return i;
		}
	}
	return -1;
}

int targetpid_exist(uint32_t pid){
	for(int i=0; i<target_index; i++){
		if (pid == targetpid[i]){
			return i;
		}
	}
	return -1;
}

int targetcr3_exist(uint32_t cr3){
	for(int i=0; i<target_index; i++){
		if (cr3 == targetcr3[i]){
			return i;
		}
	}
	return -1;
}

static void runTests(void);

static void callbacktests_printSummary(void);
static void callbacktests_resetTests(void);


static int count = 0;
static int poll = 0;
static int api_time = 0;


static plugin_interface_t keylogger_interface;

DECAF_Handle handle_ins_end_cb = DECAF_NULL_HANDLE;
DECAF_Handle handle_block_end_cb = DECAF_NULL_HANDLE;
DECAF_Handle handle_block_begin_cb = DECAF_NULL_HANDLE;
FILE * keylogger_log=DECAF_NULL_HANDLE;

#define MAX_STACK_SIZE 5000
char modname_t[512];
char func_name_t[512];
uint32_t sys_call_ret_stack[MAX_STACK_SIZE];
uint32_t sys_call_entry_stack[MAX_STACK_SIZE];
uint32_t cr3_stack[MAX_STACK_SIZE];
uint32_t stack_top = 0;
void check_call(DECAF_Callback_Params *param)
{
	CPUState *env=param->be.env;
	CPUArchState *mips_env = env->env_ptr;
	if(env == NULL)
	return;
	target_ulong pc = param->be.next_pc;
	target_ulong cr3 = DECAF_getPGD(env) ;
	if(stack_top == MAX_STACK_SIZE)
	{
     //if the stack reaches to the max size, we ignore the data from stack bottom to MAX_STACK_SIZE/10
		memcpy(sys_call_ret_stack,&sys_call_ret_stack[MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		memcpy(sys_call_entry_stack,&sys_call_entry_stack[MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		memcpy(cr3_stack,&cr3_stack[MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		stack_top = MAX_STACK_SIZE-MAX_STACK_SIZE/10;
		return;
	}

	//DECAF_read_mem(env,mips_env->active_tc.gpr[28],4,&sys_call_ret_stack[stack_top]);
	sys_call_entry_stack[stack_top] = pc;
	cr3_stack[stack_top] = cr3;
	stack_top++;




}
void check_ret(DECAF_Callback_Params *param)
{
	if(!stack_top)
		return;
	if(stack_top > 0){
		if(param->be.next_pc == sys_call_entry_stack[stack_top-1])
		{
			stack_top--;
		}
		else if(param->be.next_pc > 0x80000000){
			DECAF_printf("jump into kernel, maybe not overflow\n");
		} 
		else{
			DECAF_printf("stack overflow:%x, %x, %d\n", param->be.next_pc, sys_call_entry_stack[stack_top-1], stack_top - 1);

			for(int i=0;i< stack_top;i++){
				DECAF_printf("%d:%x\n",i,sys_call_entry_stack[i]);
			}
			DECAF_printf("checke ret done work\n");
			doneWork(32);
		}
	}
	
}


extern int fla;

void stopWork(){
	stopTrace();
	DECAF_printf("time is up\n");
	afl_fork = 0;
	targetpid[1]=0;
	targetcr3[1]=0;	
	endWork();
}

static void do_block_begin(DECAF_Callback_Params* param)
{

	if(param->bb.tb->pc == 	0x805510f0){ //egrep ' (panic|log_store)$' /proc/kallsyms
		DECAF_printf("kernel panic\n");
		doneWork(32);
	}
	CPUArchState *cpu = param->bb.env->env_ptr;
	target_ulong pc = param->bb.tb->pc;
	target_ulong pgd = DECAF_getPGD(param->bb.env);
	int index = targetcr3_exist(pgd);
	char cur_process[512];
	int pid;
	VMI_find_process_by_cr3_c(pgd, cur_process, 512, &pid);
	if(index == -1)
	{
		int index = target_exist(cur_process);
		if(index != -1)
		{
			targetcr3[index] = pgd;
			targetpid[index] = pid;
		}
		else{
			return;
		}
	}
	//DECAF_printf("%s:%d:block begin:%x,pgd:%x\n", cur_process, pid, pc, pgd);


	char modname[512];
	char functionname[512];
	fla = 1;
	//if(pc == 0x401c70) 
	//0x76f4f144 0x77b62a2c 0x77cbfa00
	if(pc == 0x401c70 || pc == 0x401c7c || pc > 0x80000000)
		return;
	if(strcmp(cur_process, "hedwig.cgi") == 0)
		return;
	//DECAF_printf("pc is %x\n", pc);
	if (0 == funcmap_get_name_c(pc, pgd, &modname, &functionname)) {
		
		//DECAF_printf("functiona %s\n", functionname);
		if(strcmp(functionname, "__libc_accept") == 0 ) //strcmp(functionname, "accept") == 0 || 
		{
			gettimeofday(&tv_api, NULL);
			accept_block = 1;
			DECAF_printf("cur_pro:%s, function:%s, pc:%x, time:%d,%d\n", cur_process, functionname, pc, tv_api.tv_sec, tv_api.tv_usec);	
		}

		else if(strcmp(functionname, "execve") == 0 || strcmp(functionname, "spawn") == 0){

			target_ulong a0 = cpu->active_tc.gpr[4];//path
			target_ulong a1 = cpu->active_tc.gpr[5];//argv
			target_ulong a2 = cpu->active_tc.gpr[6];//envp
			target_ulong addr;
			char tmpBuf[8600];
			target_ulong i = a2;
			DECAF_read_mem(param->bb.env, i, 4, &addr);
			while(addr!=0){				
				memset(tmpBuf, 0, 500);
				DECAF_read_mem(param->bb.env, addr, 500, tmpBuf);
				//DECAF_printf("cur_pro:%s, %x,function:%s,%x,%s\n", cur_process, pc, functionname, addr, tmpBuf);
	
				if(strstr(tmpBuf, "HTTP_COOKIE")){
				//if(strstr(tmpBuf, "SERVER_SOFTWARE")){		
					//DECAF_printf("cur_pro:%s, %x,function:%s,%x,%s\n", cur_process, pc, functionname, addr, tmpBuf);
					if(afl_begin == 1 && afl_fork == 0){
						afl_fork = 1;	
						char * tmp_buf;
						tmp_buf = (char *)malloc(4096);
						memset(tmp_buf, 0, 4096);
						u_long bufsz = 4096;
						char filename[500];
						ulong sz = getWork(cpu, tmp_buf, bufsz);
						startTrace(cpu, 0x400000L, 0x500000L);
						orig_data = current_data = tmp_buf;
						rest_len = sz; 
						gettimeofday(&tv_api, NULL);
						//if(rest_len > 8600) rest_len = 8600 - strlen("HTTP_COOKIE=") -1;
						//DECAF_printf("pc:%x,time:%d,%d,len %d, current data is %s\n", pc, tv_api.tv_sec, tv_api.tv_usec, rest_len, current_data);// current_data
						DECAF_write_mem(param->bb.env, addr + strlen("HTTP_COOKIE="), rest_len, current_data);
						//cpu->active_tc.gpr[2] = rest_len + strlen("SERVER_SOFTWARE="); // not the same as read
						rest_len = 0;
					}
					//memset(tmpBuf, 0, 500);
					//DECAF_read_mem(param->bb.env, addr, 8600, tmpBuf);
					//DECAF_printf("cur_pro:%s, %x,function:%s,%x,%s\n", cur_process, pc, functionname, addr, tmpBuf);
				}
				

				i+=4;
				DECAF_read_mem(param->bb.env, i, 4, &addr);
			}
		
				
		}

		else if(strcmp(functionname, "poll") == 0)
		{	
			DECAF_printf("cur_pro:%s, function %s, mod:%s,pc:%x\n", cur_process, functionname, modname, pc);

		}
/*
		else if(strcmp(functionname, "read") == 0){
			DECAF_printf("cur_pro:%s, function %s, mod:%s,pc:%x\n", cur_process, functionname, modname, pc);				
		}
*/
		else if(strcmp(functionname, "__libc_read")==0 && strcmp(cur_process,"httpd") == 0) {
//after snapshot
			target_ulong a0 = cpu->active_tc.gpr[4];//fd
			target_ulong a2 = cpu->active_tc.gpr[6];//nbytes
			//DECAF_printf("cur_pro:%s, a0:%x, current_fd:%x, pc:%x\n",cur_process, a0, current_fd, pc);	
			if(a0 == current_fd){
				network_read_block = 1;
/*
				struct itimerval tick;
				memset(&tick, 0, sizeof(tick));    
				tick.it_value.tv_sec = 0;  // sec  
				tick.it_value.tv_usec = 500000; // micro sec
				int ret = setitimer(ITIMER_REAL, &tick, NULL);  
				if(ret) DECAF_printf("set timer failed\n");
*/
			}
		}
		//return;
	}




	if(pc > 0x50000000)	
		return;
	if(pc == 0x407230) //before read
	{
		
	}
	if(pc == 0x403470) //before spawn
	{
		
	}
	if(pc == 0x403148) // before process_cgi
	{
		
	}
	if(pc == 0x406db4) // before process_cgi
	{
		if(afl_begin == 0){	
			afl_begin = 1;
			DECAF_printf("snapshot create\n");
			//startForkserver(cpu, enableTimer);
			startCreatesnapshot(cpu, enableTimer);
			DECAF_printf("snapshot create after\n");
		}
	}
	//printf("pc:%x, cur_proc:%s, pgd:%x\n", pc, cur_process, pgd);
	if(accept_block == 1 ){ // after accept //&& 0x406a18 pc == 0x4002b8
		accept_block = 0;
		target_ulong v0 = cpu->active_tc.gpr[2];//return value (fd)
		if (v0!=0 && v0!=0xffffffff){
			current_fd = v0;
			DECAF_printf("accept fd:%x, pc:%x\n", current_fd, pc);
		}
	}
	else if(network_read_block == 1){//after read // &&0x4072f8, pc == 0x4002f4
		network_read_block = 0; 

		CPUArchState *cpu = param->bb.env->env_ptr;
		target_ulong pc = cpu->active_tc.PC;
		target_ulong a0 = cpu->active_tc.gpr[4];//fd
		target_ulong a1 = cpu->active_tc.gpr[5];//buf
		target_ulong a2 = cpu->active_tc.gpr[6];//nbytes
		target_ulong v0 = cpu->active_tc.gpr[2];//return value (read)
	
		char tmp_buf[4096];
		memset(tmp_buf, 0, 4096);

		target_ulong len = readFile("/home/zyw/experiment/TriforceAFL_new/inputs_bak/nor_sample", tmp_buf, 4096);

		gettimeofday(&tv_api, NULL);
		DECAF_printf("pc:%x, len:%d, current data is %s\n", pc, len, tmp_buf);// current_data

		DECAF_write_mem(param->bb.env, a1, len, tmp_buf);
		cpu->active_tc.gpr[2] = len;//need to modify v0

	}

}

static void do_block_end(DECAF_Callback_Params* param){	

	CPUArchState *cpu = param->be.env->env_ptr;
	target_ulong pc = param->be.cur_pc;
	target_ulong bk_pc = param->be.tb->pc;
	target_ulong pgd = DECAF_getPGD(param->be.env);
	int index = targetcr3_exist(pgd);
	if(index == -1)
		return;

	char cur_process[512];
	int pid;
	VMI_find_process_by_cr3_c(pgd, cur_process, 512, &pid);
	//DECAF_printf("%s:%d:block end:%x\n", cur_process, pid, bk_pc);
	
	if(strcmp(cur_process, "hedwig.cgi") != 0) // NEED CHANGE
		return;
	if(pc > 0x80000000)
		return;

//NEED CHANGE
	if(pc >= 0x419470 && pc <= 0x41991c) //.MIPS.stubs for hedwig.cgi(cgibin)
		return;
/*
	if(pc >= 0x411910 && pc <= 0x411f7c)//.MIPS.stubs for httpd
		return;
*/
	unsigned char insn_buf[4];
	int is_call = 0, is_ret = 0;

	DECAF_read_mem(param->be.env,pc - 4 ,sizeof(char)*4,insn_buf);
	if(insn_buf[0] == 9 && (insn_buf[1]&7) == 0 && (insn_buf[2]&31) == 0 && (insn_buf[3]&252) == 0){ //jalr
		param->be.next_pc = param->be.cur_pc + 4;
		int jump_reg = (insn_buf[3] * 8) + (insn_buf[2]/32);
		int next_reg = insn_buf[1]/8;			
		
		int jump_addr = cpu->active_tc.gpr[jump_reg];
		if(jump_addr > 0x80000000)
			return;
		
		int jump_value = ((CPUArchState *)param->be.env->env_ptr)->active_tc.gpr[25];
		//DECAF_printf("jalr ins:%x, next pc:%x, jalr reg:%d, jalr next reg:%d\n",param->be.cur_pc, param->be.next_pc, jump_reg, next_reg);
		if(next_reg == 31){
			is_call = 1;
		}
	}else if((insn_buf[3] & 252) == 12){ //jal
		param->be.next_pc = param->be.cur_pc + 4;
		int jump_addr = insn_buf[0] + insn_buf[1]*256 + insn_buf[2]* 256*256;
		if(jump_addr > 0x80000000)
			//DECAF_printf("jal:%x\n", jump_addr);
			return;
		//DECAF_printf("jal ins:%x, next pc:%x\n",param->be.cur_pc, param->be.next_pc);
		is_call = 1;
	}else if((insn_buf[0] & 63) == 8 && insn_buf[1] == 0 && (insn_buf[2]&31) == 0 && (insn_buf[3]&252) == 0){
		int reg = (insn_buf[3] *8) + (insn_buf[2]/32);
		if(reg == 31){ 
			//jr $ra, not jr other(such as jr $t9, jump at the end of function)
			int jump_addr = cpu->active_tc.gpr[reg];
			if(jump_addr > 0x80000000)
				return;	
			//DECAF_printf("jr ins:%x, next pc:%x, jr reg:%d\n",param->be.cur_pc, param->be.next_pc, reg);	
			is_ret = 1;
		}
		else if(reg == 25){
			//jr $ra happens in lib function
			//if(param->be.cur_pc < 0x70000000){
			//DECAF_printf("jr ins:%x, next pc:%x, jr reg:%d\n",param->be.cur_pc, param->be.next_pc, reg);
			//}



/*
			if(stack_top > 0){
				stack_top --;
			}
*/
		}	
	}

	if (is_call)
	check_call(param);
	else if (is_ret)
	check_ret(param);


}



void do_callbacktests(Monitor* mon, const QDict* qdict)
{
  if ((qdict != NULL) && (qdict_haskey(qdict, "procname")))
  {
 
    strncpy(targetname[target_index], qdict_get_str(qdict, "procname"), 512);
    targetname[target_index][511] = '\0';
    target_index++;
  }
}

static void callbacktests_loadmainmodule_callback(VMI_Callback_Params* params)
{
	char procname[64];
	uint32_t pid;
	if (params == NULL)
	{
		return;
	}

	VMI_find_process_by_cr3_c(params->cp.cr3, procname, 64, &pid);

	if (pid == (uint32_t)(-1))
	{
		return;
	}
	int index = target_exist(procname);
	if (index != -1)
	{
		gettimeofday(&tv_api, NULL);
		DECAF_printf("\nProcname:%s/%d,pid:%d, cr3:%x start, time:%d,%d\n",procname, index, pid, params->cp.cr3, tv_api.tv_sec, tv_api.tv_usec);
		targetpid[index] = pid;
		targetcr3[index] = params->cp.cr3;
	}
}

static void callbacktests_removeproc_callback(VMI_Callback_Params* params)
{

  	char procname[64];
	uint32_t pid;

	if (params == NULL)
	{
		return;
	}
	VMI_find_process_by_cr3_c(params->rp.cr3, procname, 64, &pid);
	
	if (pid == (uint32_t)(-1))
	{
		return;
	}
	int index = target_exist(procname);
	if (index != -1)
	{
		stack_top = 0; //??????????????????????????? http end
		gettimeofday(&tv_api, NULL);
		DECAF_printf("\nProcname:%s/%d,pid:%d, cr3:%x end, time:%d,%d\n",procname, index, pid, params->rp.cr3,  tv_api.tv_sec, tv_api.tv_usec);
		//targetpid[index] = 0;
		//targetcr3[index] = 0;
		if(strcmp(procname, "hedwig.cgi")==0) //NEED CHANGE
		//if(strcmp(procname, "execv_sample")==0)
		{
			stopTrace();
			//DECAF_printf("%s doneWork\n", procname);	
			//doneWork(0);
			afl_fork = 0;
			//network_read_block = 1; //change before/after create snapshot.
//zyw ?
			targetpid[1]=0;
			targetcr3[1]=0;		
		
			struct itimerval tick;
			memset(&tick, 0, sizeof(tick));    
			tick.it_value.tv_sec = 0;  // sec  
			tick.it_value.tv_usec = 0; // micro sec
			int ret = setitimer(ITIMER_REAL, &tick, NULL);  
			if(ret) DECAF_printf("cancel timer failed\n");

			endWork();
		}
	}

	

	//unregister the callback FIRST before getting the time of day - so
	// we don't get any unnecessary callbacks (although we shouldn't
	// since the guest should be paused.... right?)
/*
	DECAF_printf("unregister handle %x\n", callbacktests[index].handle);
	DECAF_unregister_callback(callbacktests[index].cbtype, callbacktests[index].handle);
	callbacktests[index].handle = DECAF_NULL_HANDLE;
	DECAF_printf("Callback Count = %u\n", callbacktests[index].count);

	gettimeofday(&callbacktests[index].tock, NULL);

	elapsedtime = (double)callbacktests[index].tock.tv_sec + ((double)callbacktests[index].tock.tv_usec / 1000000.0);
	elapsedtime -= ((double)callbacktests[index].tick.tv_sec + ((double)callbacktests[index].tick.tv_usec / 1000000.0));
	DECAF_printf("Process [%s] with pid [%d] ended at %u:%u\n", callbacktests[index].name, params->rp.pid, callbacktests[index].tock.tv_sec, callbacktests[index].tock.tv_usec);
	DECAF_printf("  Elapsed time = %0.6f seconds\n\n", elapsedtime);
*/
}

static int callbacktests_init(void)
{
	DECAF_output_init(NULL);
	DECAF_printf("Hello World\n");

	target_main_address[0] = 0x40a218; //httpd
	target_main_address[1] = 0x4023e0; //hedwig.cgi

	processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB, &callbacktests_loadmainmodule_callback, NULL);
	removeproc_handle = VMI_register_callback(VMI_REMOVEPROC_CB, &callbacktests_removeproc_callback, NULL);
	block_begin_handle = DECAF_registerOptimizedBlockBeginCallback(&do_block_begin, NULL, INV_ADDR, OCB_ALL);
	block_end_handle = DECAF_registerOptimizedBlockEndCallback(&do_block_end, NULL, INV_ADDR, INV_ADDR);
	for(int i = 0; i < PRO_MAX_NUM; i++){	
		targetcr3[i] = 0;
		targetpid[i] = 0;
		targetname[i][0] = '\0';
	}
  	return (0);
}


static void callbacktests_cleanup(void)
{
  VMI_Callback_Params params;

  DECAF_printf("Bye world\n");

  if (processbegin_handle != DECAF_NULL_HANDLE)
  {
    VMI_unregister_callback(VMI_CREATEPROC_CB, processbegin_handle);
    processbegin_handle = DECAF_NULL_HANDLE;
  }

  if (removeproc_handle != DECAF_NULL_HANDLE)
  {
    VMI_unregister_callback(VMI_REMOVEPROC_CB, removeproc_handle);
    removeproc_handle = DECAF_NULL_HANDLE;
  }

  //make one final call to removeproc to finish any currently running tests
  if (targetpid != (uint32_t)(-1))
  {
    params.rp.pid = targetpid;
    callbacktests_removeproc_callback(&params);
  }
}

#ifdef __cplusplus
extern "C"
{
#endif

static mon_cmd_t callbacktests_term_cmds[] = {
  #include "plugin_cmds.h"
  {NULL, NULL, },
};

#ifdef __cplusplus
}
#endif

plugin_interface_t* init_plugin(void)
{
  callbacktests_interface.mon_cmds = callbacktests_term_cmds;
  callbacktests_interface.plugin_cleanup = &callbacktests_cleanup;
  signal(SIGALRM, stopWork);
  //initialize the plugin
  callbacktests_init();
  return (&callbacktests_interface);
}

