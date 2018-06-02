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
static DECAF_Handle mem_write_cb_handle = DECAF_NULL_HANDLE;
#define PRO_MAX_NUM 10
static char targetname[PRO_MAX_NUM][512];// 10 program, such as httpd, hedwig.cig
static uint32_t targetcr3[PRO_MAX_NUM];// 10 program, such as httpd, hedwig.cig
static uint32_t targetpid[PRO_MAX_NUM];// 10 program, such as httpd, hedwig.cig
static int target_main_address[PRO_MAX_NUM];

static int target_index = 0; //the number of target program

//zyw
extern int helper_flag;
extern int helper_ASID[2];


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

extern uint32_t sys_call_ret_stack[2][MAX_STACK_SIZE];
extern uint32_t sys_call_entry_stack[2][MAX_STACK_SIZE];
extern uint32_t cr3_stack[2][MAX_STACK_SIZE];
extern uint32_t stack_top[2];

extern uint32_t saved_stack[2][MAX_STACK_SIZE];
extern uint32_t saved_stack_top[2];

void check_call(DECAF_Callback_Params *param, int index)
{
	//DECAF_printf("check_call:%d\n", index);
	CPUState *env=param->be.env;
	CPUArchState *mips_env = env->env_ptr;
	if(env == NULL)
	return;
	target_ulong pc = param->be.next_pc;
	target_ulong cr3 = DECAF_getPGD(env) ;
	if(stack_top[index] == MAX_STACK_SIZE)
	{
     //if the stack reaches to the max size, we ignore the data from stack bottom to MAX_STACK_SIZE/10
		memcpy(sys_call_ret_stack[index],&sys_call_ret_stack[index][MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		memcpy(sys_call_entry_stack[index],&sys_call_entry_stack[index][MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		memcpy(cr3_stack,&cr3_stack[index][MAX_STACK_SIZE/10],MAX_STACK_SIZE-MAX_STACK_SIZE/10);
		stack_top[index] = MAX_STACK_SIZE-MAX_STACK_SIZE/10;
		return;
	}

	//DECAF_read_mem(env,mips_env->active_tc.gpr[28],4,&sys_call_ret_stack[stack_top]);
	sys_call_entry_stack[index][stack_top[index]] = pc;
	cr3_stack[index][stack_top[index]] = cr3;
	stack_top[index]++;




}


void check_ret(DECAF_Callback_Params *param, int index)
{
	//DECAF_printf("check_ret:%d\n", index);
	if(!stack_top[index])
		return;
	if(stack_top[index] > 0){
		if(param->be.next_pc == sys_call_entry_stack[index][stack_top[index]-1])
		{
			stack_top[index]--;
		}
		else if(param->be.next_pc > 0x80000000){
			DECAF_printf("jump into kernel, maybe not overflow\n");
		} 
		else{
			DECAF_printf("stack overflow(%d):%x, %x, %d\n", index, param->be.next_pc, sys_call_entry_stack[index][stack_top[index]-1], stack_top[index] - 1);

			for(int i=0;i< stack_top[index];i++){
				DECAF_printf("%d:%x\n",i,sys_call_entry_stack[index][i]);
				sleep(10000);
			}
			//DECAF_printf("checke ret done work\n");
			endWork(32);
			//doneWork(32);
		}
	}
	
}



void stopWork(){
	stopTrace();
	DECAF_printf("time is up\n");
	afl_fork = 0;
	targetpid[1]=0;
	targetcr3[1]=0;	
	//endWork(0);
}


//int do_block_begin_flag = 0;
int after = 0;
extern int fcntl_start;

static void do_block_begin(DECAF_Callback_Params* param)
{
/*
	if(param->bb.tb->pc == 	0x805510f0){ //egrep ' (panic|log_store)$' /proc/kallsyms
		DECAF_printf("kernel panic\n");
		doneWork(32);
	}
*/
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
			//if(helper_flag == 1) DECAF_printf("pid:%d,proc:%s\n", pid, cur_process);
			return;
		}
	}
	else{
		index = target_exist(cur_process); //sometimes the pgd of child program is the same as parent program. need to recalculate the index
		if(index == -1) return; // cur_process is null, pid is 0
	}
	//DECAF_printf("%s:%d:block begin:%x,pgd:%x\n", cur_process, pid, pc, pgd);
/*
	if(do_block_begin_flag%100 == 0)
	{
		//DECAF_printf("cr is %x,pid is %d\n",pgd, pid);
		for (int i = 0; i < cpu->tlb->tlb_in_use; i++) {
			r4k_tlb_t *tlb = &cpu->tlb->mmu.r4k.tlb[i];
			target_ulong mask = tlb->PageMask | ~(TARGET_PAGE_MASK << 1);
			target_ulong VPN = tlb->VPN & ~mask;
			int n = !!(0x404a4c & mask & ~(mask >> 1));//n=0?
			target_ulong physical = tlb->PFN[n] | (0x404a4c & (mask >> 1));
			//DECAF_printf("callbacktest virtual:%x,physical:%x,n:%d\n", VPN, physical,n);

		}
		for(int i =0; i < 256; i++){
			//int addr = VPN;			
			int mmu_idx = 2;
			//int index = (addr >> 12) & (256 - 1);
			//haddr = addr + cpu->tlb_table[mmu_idx][index].addend;]
			if(cpu->tlb_table[mmu_idx][i].addend != -1){
				//DECAF_printf("addend is %x\n", cpu->tlb_table[mmu_idx][i].addend);
			}
		}		
		//DECAF_printf("\n\n");


	}
	do_block_begin_flag ++;
*/

	helper_ASID[index] = cpu->CP0_EntryHi & cpu->CP0_EntryHi_ASID_mask; //zyw
	//if(pc < 0x70000000 && after == 1){ DECAF_printf("pc:%x, cur_proc:%s, pgd:%x\n", pc, cur_process, pgd); }//after = 0;}

	char modname[512];
	char functionname[512];

//tmporary, after read stop and reload snapshot
/*
	if(pc == 0x406d6c){
		target_ulong sp = cpu->active_tc.gpr[29];//sp
		target_ulong ra_addr = sp + 0x16c;
		target_ulong ra;
		DECAF_read_mem(param->bb.env, ra_addr, sizeof(ra), &ra);
		//DECAF_printf("ra is %x\n", ra);
	}
*/

	if(pc == 0x407e1c){
		target_ulong s0 = cpu->active_tc.gpr[16];//s0
		DECAF_printf("s0s0s0s0 is %x\n", s0);
		
	}
	if(pc == 0x406234){
		target_ulong v0 = cpu->active_tc.gpr[2];//s0
		DECAF_printf("v0v0v0 is %x\n", v0);
	} 
	if(pc == 0x407348 && after == 1){ //NEED CHANGE  0x407bf0

		DECAF_printf("after read\n");
/*
		//user_forkpt = cpu->active_tc.gpr[29];//sp
		DECAF_printf("donestate restart_cpu:%x, user_forkpt:%x, user_stack:%x, len:%d\n",param->bb.env, user_forkpt, user_stack, user_origpt-user_forkpt);
		if(user_origpt-user_forkpt < 0) exit(32);
		cpu_memory_rw_debug(param->bb.env, user_forkpt, user_stack, user_origpt-user_forkpt, 0);
		DECAF_printf("sp:%x\n",cpu->active_tc.gpr[29]);
		for(int i=0;i<1000;i++)
		{
			if(user_stack[i]!=0){
				printf("%x ",user_stack[i]);
			}
		 }
*/
		//loadCPUState(cpu);
		doneWork(0);
		//return;
/*	
		stopTrace();
		//DECAF_printf("%s doneWork\n", procname);	
		//doneWork(0);
		afl_fork = 0;
		//network_read_block = 1; //change before/after create snapshot.

		targetpid[1]=0;
		targetcr3[1]=0;		
	
		struct itimerval tick;
		memset(&tick, 0, sizeof(tick));    
		tick.it_value.tv_sec = 0;  // sec  
		tick.it_value.tv_usec = 0; // micro sec
		int ret = setitimer(ITIMER_REAL, &tick, NULL);  
		if(ret) DECAF_printf("cancel timer failed\n");
		//doneWork(0);//NEED CHANGE
		DECAF_printf("hedwig end work\n");
		endWork(0);
*/	
	}
//

/*
	if(pc == 0x40a41c || pc == 0x40a42c)
		return;
	if(pc == 0x404ac8)
		DECAF_printf("v0 is %x\n", cpu->active_tc.gpr[2]);
*/
	//if(pc < 0x70000000)
		//DECAF_printf("callbacktest pc is %x, s3 is %x\n", pc, cpu->active_tc.gpr[19]);
		
//binary modification to improve fuzzing speed	
	if(strcmp(cur_process, "hedwig.cgi") == 0) 
	{

		if(pc  == 0x419610){//select
			//target_ulong s7 = cpu->active_tc.gpr[23];//timeout
			target_ulong sp = cpu->active_tc.gpr[29];//sp
			target_ulong sp_10 = sp + 0x10;//timeout the fifth arg
			target_ulong time_addr;
			struct timeval time;
			DECAF_read_mem(param->bb.env, sp_10, sizeof(target_ulong), &time_addr);
			//DECAF_read_mem(param->bb.env, time_addr, sizeof(struct timeval), &time);
			//DECAF_printf("cur_pro:%s, function:%s, pc:%x, time:%d,%d\n", cur_process, functionname, pc, time.tv_sec, time.tv_usec);
			time.tv_sec = 0;
			time.tv_usec = 0;
			DECAF_write_mem(param->bb.env, time_addr, sizeof(struct timeval), &time);
			//DECAF_printf("cur_pro:%s, function:%s, pc:%x, time:%d,%d\n", cur_process, functionname, pc, time.tv_sec, time.tv_usec);
		}
		return;

	}
	
	if (0 == funcmap_get_name_c(pc, pgd, &modname, &functionname)) {
		if(strstr(functionname, "_dl")!=NULL)
			return;
		//if(after == 1) DECAF_printf("functiona %s\n", functionname);
		if(strcmp(functionname, "fopen") == 0)
		{
			
		}
		else if(strcmp(functionname, "getaddrinfo") == 0 || strcmp(functionname, "_getaddrinfo") == 0)
		{	
			target_ulong a0 = cpu->active_tc.gpr[4];//fd
			char tmpBuf[50];
			memset(tmpBuf, 0, 50);
			DECAF_read_mem(param->bb.env, a0, 50, tmpBuf);
			DECAF_printf("%s, %s,%s,%x\n", cur_process,functionname, tmpBuf, pc);
		}
		
		else if(strcmp(functionname, "__libc_accept") == 0 || strcmp(functionname, "accept") == 0)
		{
			accept_block = 1;
			DECAF_printf("cur_pro:%s, function:%s, pc:%x\n", cur_process,functionname, pc);
			return;
		}

		else if(strcmp(functionname, "execve") == 0 || strcmp(functionname, "spawn") == 0){

			target_ulong a0 = cpu->active_tc.gpr[4];//fd
			char tmpBuf[50];
			memset(tmpBuf, 0, 50);
			DECAF_read_mem(param->bb.env, a0, 50, tmpBuf);
			DECAF_printf("%s, execv,%s,%x\n", cur_process, tmpBuf, pc);
			return;


			
		}

		else if(strcmp(functionname, "poll") == 0)
		{	
			DECAF_printf("cur_pro:%s, function %s, mod:%s,pc:%x\n", cur_process, functionname, modname, pc);

		}

		else if(strcmp(functionname, "__libc_read")==0 || strcmp(functionname, "read")==0) 
		{
			target_ulong a0 = cpu->active_tc.gpr[4];//fd
			target_ulong a2 = cpu->active_tc.gpr[6];//nbytes
			//DECAF_printf("cur_pro:%s, a0:%x, current_fd:%x, pc:%x\n",cur_process, a0, current_fd, pc);	
			if(a0 == current_fd){
				network_read_block = 1;
			}
			return;
		}
		else if(strcmp(functionname, "sleep") == 0)
		{
			stopTrace();
			afl_fork = 0;
			targetpid[0]=0;
			targetcr3[0]=0;		
		
			struct itimerval tick;
			memset(&tick, 0, sizeof(tick));    
			tick.it_value.tv_sec = 0;  // sec  
			tick.it_value.tv_usec = 0; // micro sec
			int ret = setitimer(ITIMER_REAL, &tick, NULL);  
			if(ret) DECAF_printf("cancel timer failed\n");
			DECAF_printf("sleep end work\n\n");
			//doneWork(0); //need change
			//endWork(0);
		}
		else if(strcmp(functionname, "__libc_fcntl") == 0)
		{
			fcntl_start = 1;
			target_ulong a0 = cpu->active_tc.gpr[4];//fd
			int tmpBuf;
			DECAF_read_mem(param->bb.env, a0, 4, &tmpBuf);
			DECAF_printf("%s, %s,%x,%x\n", cur_process,functionname, tmpBuf, pc);
		}
	}
	
	if(pc >= 0x80000000 && kernel_stack_count == 0)
	{
		kernel_stack_count = 1;
		kernel_origpt = cpu->active_tc.gpr[29];
		DECAF_printf("%s kernel stack:%x\n",cur_process, kernel_origpt);
	}
	else if(pc < 0x80000000 && user_stack_count == 0)
	{
		user_stack_count = 1;
		user_origpt = cpu->active_tc.gpr[29];
		DECAF_printf("user stack:%x\n", user_origpt);
	}
	

	if(pc > 0x50000000)	
		return;

	if(accept_block == 1){ 
		accept_block = 0;
		target_ulong v0 = cpu->active_tc.gpr[2];//return value (fd)
		if (v0!=0 && v0!=0xffffffff){
			current_fd = v0;
			DECAF_printf("accept fd:%x, pc:%x\n", current_fd, pc);
			afl_begin = 1;
			//user_forkpt = cpu->active_tc.gpr[29];
			//DECAF_printf("current pc:%x, stack:%x\n", pc, user_forkpt);
			after = 1;
//NEED CHANGE			
				
			startForkserver(cpu, enableTimer);
			//startFork(cpu, enableTimer);
			//startCreatesnapshot(cpu, enableTimer);
			//storeCPUState(cpu); 
			
		}
	}

	else if(network_read_block == 1){
		network_read_block = 0; 
		CPUArchState *cpu = param->bb.env->env_ptr;
		target_ulong pc = cpu->active_tc.PC;
		target_ulong a0 = cpu->active_tc.gpr[4];//fd
		target_ulong a1 = cpu->active_tc.gpr[5];//buf
		target_ulong a2 = cpu->active_tc.gpr[6];//nbytes
		target_ulong v0 = cpu->active_tc.gpr[2];//return value (read)
	
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
		}
		struct itimerval tick;
		gettimeofday(&tv_api, NULL);
		DECAF_printf("pc:%x,time:%d,%d, current data is %s\n", pc, tv_api.tv_sec, tv_api.tv_usec, current_data);// current_data

		if(rest_len != 0){// rest_len is the length of virtual buffer
			if (rest_len + 1 >= a2){// a2 is the maximum recv length for once
				DECAF_write_mem(param->bb.env, a1, a2, current_data);
				cpu->active_tc.gpr[2] = a2;//need to modify v0
				current_data += a2;
				rest_len -= a2;
			}
			else{

				DECAF_write_mem(param->bb.env, a1, rest_len, current_data);
				cpu->active_tc.gpr[2] = rest_len;//need to modify v0
				current_data += rest_len;
				rest_len = 0;
			}	

		}

		else{// if input data's data is too little, it will end up with donework
			DECAF_printf("		donework done:%d,  parent pid:%d\n",getpid(), getppid());
			free(buf); //current_data 
		}

	}

}

static void do_block_end(DECAF_Callback_Params* param){	


	CPUArchState *cpu = param->be.env->env_ptr;
	target_ulong pc = param->be.cur_pc;
	target_ulong bk_pc = param->be.tb->pc;
	target_ulong pgd = DECAF_getPGD(param->be.env);
	int index = targetcr3_exist(pgd);
	char cur_process[512];
	int pid;
	VMI_find_process_by_cr3_c(pgd, cur_process, 512, &pid);
	if(index == -1)
	{
		index = target_exist(cur_process);
		if(index != -1)
		{
			targetcr3[index] = pgd;
			targetpid[index] = pid;
		}
		else{
			return;
		}
	}
	else{
		index = target_exist(cur_process); //sometimes the pgd of child program is the same as parent program. need to recalculate the index
		if(index == -1) return; // cur_process is null, pid is 0
	}

	if(pc > 0x80000000)
		return;


//NEED CHANGE
	if(index == 1){

		if(pc >= 0x419470 && pc <= 0x41991c) //.MIPS.stubs for hedwig.cgi(cgibin)
			return;
	}
	if(index == 0){
		if(pc >= 0x411910 && pc <= 0x411f7c)//.MIPS.stubs for httpd
			return;
	}

//

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
	}else if((insn_buf[3] == 0x04) && (insn_buf[2] == 0x11)){ //bal;
		param->be.next_pc = param->be.cur_pc + 4;
		int offset = insn_buf[1] * 1024 + insn_buf[0] * 4;
		int jump_addr =  param->be.cur_pc + offset;
		if(jump_addr > 0x80000000)
			//DECAF_printf("jal:%x\n", jump_addr);
			return;
		if(offset <= 4) //bal the next pc
			return;
		//DECAF_printf("bal ins:%x, next pc:%x, jmp pc:%x\n",param->be.cur_pc, param->be.next_pc, offset);
		is_call = 1;	
	}

	//if (is_call)
	//check_call(param, index);
	//else if (is_ret)
	//check_ret(param, index);

}

static void fuzz_mem_write(DECAF_Callback_Params *dcp)
{
	if(afl_begin == 1)
	{
		uint32_t virt_addr=dcp->mw.vaddr;
		int size = dcp->mw.dt;
		//DECAF_printf("write addr:%x, size:%x\n", virt, size);
	}
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

//zyw
extern uint32_t httpd_pgd;
extern int pgd_changed;
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
		helper_flag = 1;
		gettimeofday(&tv_api, NULL);
		DECAF_printf("\nProcname:%s/%d,pid:%d, cr3:%x start, time:%d,%d\n",procname, index, pid, params->cp.cr3, tv_api.tv_sec, tv_api.tv_usec);
		targetpid[index] = pid;
		targetcr3[index] = params->cp.cr3;
//NEED CHANGE
		if(strcmp(procname,"httpd") == 0)  { httpd_pgd = targetcr3[index]; pgd_changed = 1;}
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
		stack_top[index] = 0; //??????????????????????????? http end
		gettimeofday(&tv_api, NULL);
		DECAF_printf("\nProcname:%s/%d,pid:%d, cr3:%x end, time:%d,%d\n",procname, index, pid, params->rp.cr3,  tv_api.tv_sec, tv_api.tv_usec);
		//targetpid[index] = 0;
		//targetcr3[index] = 0;
		kernel_stack_count = 0;
		user_stack_count = 0;
		if(strcmp(procname, "hedwig.cgi")==0) 
		//if(strcmp(procname, "single_httpd_sa")==0)//NEED CHANGE
		{
			//stopTrace();
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
			DECAF_printf("hedwig end work\n");
			//endWork(0);
			doneWork(0);//NEED CHANGE
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
	stack_top[0] = 0;
	stack_top[1] = 0;

	processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB, &callbacktests_loadmainmodule_callback, NULL);
	removeproc_handle = VMI_register_callback(VMI_REMOVEPROC_CB, &callbacktests_removeproc_callback, NULL);
	block_begin_handle = DECAF_registerOptimizedBlockBeginCallback(&do_block_begin, NULL, INV_ADDR, OCB_ALL);
	block_end_handle = DECAF_registerOptimizedBlockEndCallback(&do_block_end, NULL, INV_ADDR, INV_ADDR);
	mem_write_cb_handle = DECAF_register_callback(DECAF_MEM_WRITE_CB,fuzz_mem_write,NULL);
					
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

