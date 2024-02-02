#include <sys/ptrace.h>
#include <stdint.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define SYSCALL_TRAP  (SIGTRAP | 0x80)

unsigned int ptrace_setoptions = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC
 | PTRACE_O_TRACEEXIT 
 |PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;
 
/*
    如何区分是syscall引发的trap还是execve引发的trap:
        PTRACE_O_TRACESYSGOOD通过设置这个选项可以知道.

    the 0x80 provides a way for the tracing parent to distinguish
	   between a syscall stop and SIGTRAP delivery 
	//ptrace_notify(SIGTRAP | ((current->ptrace & PT_TRACESYSGOOD) ? 0x80 : 0));
*/


typedef void (*callback)(int pid,struct user_regs_struct* regs);


void enter_open_syscall(int pid,struct user_regs_struct* regs){
    char buffer[0x200] = {0};
    char * addr = NULL;
    char * filename = NULL;
    char * target = NULL;

    unsigned int word;

    if(regs->orig_rax == SYS_openat){
        addr = (void*)regs->rsi;
    }else if (regs->orig_rax == SYS_open){
        addr = (void*)regs->rdi;
    }
    filename = addr;
    for(int i = 0;i<0x100 - 1;i+=4){
        word = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
        if(word < 0){
            perror("ptrace PTRACE_PEEKDATA failed");
            return;
        }
        memcpy(&buffer[i],&word,4);
        addr += 4;

        if(!buffer[i] || !buffer[i+1]||
        !buffer[i+2] || !buffer[i+3]){
            break;
        }
    }
    //printf("open file : %s",buffer);
    if((target = strstr(buffer,"flag")) != NULL){
        //printf(" - [warning] prevent to open file!");
        memcpy(target,"fuck",4);
        int i = 0;
        //重新写回去.
        while(filename < addr){
            unsigned int val = 0;
            memcpy(&val,buffer + i * 4,4);
            if(ptrace(PTRACE_POKEDATA, pid, filename, val) < 0){
                perror("ptrace PTRACE_PEEKDATA failed");
                return;
            }
            i++;
            filename+=4;
        }
    }
}


void leave_open_syscall(int pid,struct user_regs_struct* regs){
    //printf("return value: %lld \n",regs->rax);
}
//#define __NR_getdents 78
//#define __NR_getdents 64
//ssize_t getdents64(int fd, void *dirp, size_t count);


struct linux_dirent {
    unsigned long  d_ino;     /* Inode number */
    unsigned long  d_off;     /* Offset to next linux_dirent */
    unsigned short d_reclen;  /* Length of this linux_dirent */
    char           d_name[];  /* Filename (null-terminated) */
                        /* length is actually (d_reclen - 2 -
                        offsetof(struct linux_dirent, d_name)) */
    /*
    char           pad;       // Zero padding byte
    char           d_type;    // File type (only since Linux
                                // 2.6.4); offset is (d_reclen - 1)
    */
};


void leave_getdents_syscall(int pid,struct user_regs_struct* regs){
     if(regs->rax == 0xffffffffffffffff || !regs->rax){
        return;
    }
    //
    size_t len = regs->rax;
    uint64_t addr = regs->rsi;
    char* buffer = malloc(len + 0x10);
    size_t l = 0;
    uint64_t filename =  addr;

    while(l < len){
        unsigned int word = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
        if(word < 0){
            perror("ptrace PTRACE_PEEKDATA failed");
            return;
        }
        memcpy(buffer + l,&word,4);
        addr += 4;
        l+=4;
    }
    char * end = len + buffer;
    char * pos = buffer;
    int change = 0;

    while (pos < end){
        struct linux_dirent* pDirent = (struct linux_dirent*)pos;
        char * target = NULL;
        //puts(pDirent->d_name);
        pos += pDirent->d_reclen;
        ///flag filter....
        if((target = strstr(pDirent->d_name,"flag")) != NULL){
            memcpy(target,"xxxx",4);
            change = 1;
        }
    }

    l = 0;
    while(l < len){
        unsigned int val;
        memcpy(&val,buffer + l,4);
        if(ptrace(PTRACE_POKEDATA, pid, filename, val) < 0){
            perror("ptrace PTRACE_POKEDATA failed");
            return;
        }
        filename += 4;
        l+=4;
    }
}


struct linux_dirent64 {
    uint64_t        d_ino;    /* 64-bit inode number */
    uint64_t        d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};//__attribute__((packed));

void leave_getdents64_syscall(int pid,struct user_regs_struct* regs){
    // printf("leave_getdents64_syscall\n");
  //判断返回值.
    if(regs->rax == 0xffffffffffffffff || !regs->rax){
        return;
    }
    //
    size_t len = regs->rax;
    uint64_t addr = regs->rsi;
    char* buffer = malloc(len + 0x10);
    size_t l = 0;
    uint64_t filename =  addr;

    while(l < len){
        unsigned int word = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
        if(word < 0){
            perror("ptrace PTRACE_PEEKDATA failed");
            return;
        }
        memcpy(buffer + l,&word,4);
        addr += 4;
        l+=4;
    }

    char * end = len + buffer;
    char * pos = buffer;
    int change = 0;

    while (pos < end){
        struct linux_dirent64* pDirent = (struct linux_dirent64*)pos;
        char * target = NULL;
        pos += pDirent->d_reclen;
        ///flag filter....
        if((target = strstr(pDirent->d_name,"flag")) != NULL){
            memcpy(target,"xxxx",4);
            change = 1;
        }
    }

    l = 0;
    while(l < len){
        unsigned int val;
        memcpy(&val,buffer + l,4);
        if(ptrace(PTRACE_POKEDATA, pid, filename, val) < 0){
            perror("ptrace PTRACE_POKEDATA failed");
            return;
        }
        filename += 4;
        l+=4;
    }
    free(buffer);
}



void enter_execve_syscall(int pid,struct user_regs_struct* regs){
    char buffer[0x100] = {0};
    char * addr = NULL;
    char * filename = NULL;
    unsigned int word;

    if(regs->orig_rax == SYS_execveat){
        addr = (void*)regs->rsi;
    }else if (regs->orig_rax == SYS_execve){
        addr = (void*)regs->rdi;
    }
    filename = addr;
    for(int i = 0;i<0x100 - 1;i+=4){
        word = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
        memcpy(&buffer[i],&word,4);
        if(!buffer[i] || !buffer[i+1]||
        !buffer[i+2] || !buffer[i+3]){
            break;
        }
        addr += 4;
    }
    char * target = 0;
    // file protect...
    if((target = strstr(buffer,"sh")) != NULL){
        memcpy(target,"xx",2);
        int i = 0;
        //重新写回去.
        while(filename < addr){
            unsigned int val = 0;
            memcpy(&val,buffer + i * 4,4);
            if(ptrace(PTRACE_POKEDATA, pid, filename, val) < 0){
                perror("ptrace PTRACE_PEEKDATA failed");
                return;
            }
            i++;
            filename+=4;
        }
    }
    //printf("execve : %s\n",buffer);
}

void leave_execve_syscall(int pid,struct user_regs_struct* regs){
    //printf("return value: %lld \n",regs->rax);
}


void sys_log(int pid,char * syscall_name,int fd,unsigned char * buff,size_t len){
    FILE*fp = fopen("sandbox.log","a+");
    if(fp == NULL){
        perror("fopen failed");
        return;
    }

    time_t  t;
    time(&t);

    struct tm* cur_time = localtime(&t);

    fprintf(fp,"[pid : %d ,time: %02d:%02d:%02d] %s file:%d %lu bytes : ",
    pid,cur_time->tm_hour,cur_time->tm_min,cur_time->tm_sec,syscall_name,
    fd,len);

    for(size_t i = 0; i< len;i++){
        if(isprint(buff[i])){
            fputc(buff[i],fp);
        }else{
            fprintf(fp,"\\x%02x",buff[i]);
        }
    }
    fprintf(fp,"\n");
    fclose(fp);
}


void leave_read_syscall(int pid,struct user_regs_struct* regs){
    long ret = 0;
    memcpy(&ret,&regs->rax,8);

    if(ret > 0 && regs->rdi < 3){
        size_t len = ret;
        char * src_addr = (char*)regs->rsi;

        unsigned char * buff = (unsigned char*)malloc(len + 0x100);

        for(int i = 0;i<len + 0x10;i+=4){
            unsigned int word = ptrace(PTRACE_PEEKDATA, pid, src_addr, 0);
            memcpy(&buff[i],&word,8);
            src_addr += 4;
        }
        sys_log(pid,"sys_read",regs->rdi,buff,regs->rax);
    }
}

void leave_write_syscall(int pid,struct user_regs_struct* regs){
    long ret = 0;
    memcpy(&ret,&regs->rax,8);

    if(ret > 0 && regs->rdi < 3){
        size_t len = ret;
        char * src_addr = (char*)regs->rsi;

        unsigned char * buff = (unsigned char*)malloc(len + 0x100);

        for(int i = 0;i<len + 0x10;i+=4){
            unsigned int word = ptrace(PTRACE_PEEKDATA, pid, src_addr, 0);
            memcpy(&buff[i],&word,8);
            src_addr += 4;
        }
        sys_log(pid,"sys_write",regs->rdi,buff,regs->rax);
    }
}





#define MAX_SYSCALL 512
#define MAX_TASKS   1024


#define TE_EXIT         0
#define TE_SYSCALLTRAP  1
#define TE_RESTART      3
#define TE_SIGNAL_DELIVERY_STOP 4
#define TE_GROUP_STOP 5
#define TE_STOP_BEFORE_EXECVE 6                     //execve导致的暂停
#define TE_STOP_BEFORE_EXIT 7                       //exit之前导致的暂停


struct TaskCtx{
    int pos;            //在数组中的位置.
    int pid;
    int status;
    int task_event; 
    int syscall_state;
    siginfo_t si;
};

struct TaskCtx * tasks[MAX_TASKS];

struct TaskCtx *  findTask(int pid){
    for(int i = 0;i< MAX_TASKS;i++){
        if(tasks[i]&& tasks[i]->pid == pid){
            tasks[i]->pos = i;
            return tasks[i];
        }
    }
    return NULL;
}

int allocTaskPos(){
    for(int i = 0;i< MAX_TASKS;i++){
        if(tasks[i] == NULL){
            return i;
        }
    }
    return -1;
}

struct TaskCtx * allocTaskCtx(){
    struct TaskCtx * ctx = (struct TaskCtx*)calloc(1,sizeof(struct TaskCtx));
    return ctx;
}

callback enter_syscall_cb[MAX_SYSCALL];
callback leave_syscall_cb[MAX_SYSCALL];


int syscall_hook(struct TaskCtx * task){
    struct user_regs_struct regs = {0};
    
    if (ptrace(PTRACE_GETREGS,task->pid,0,&regs) < 0){
        perror("ptrace get register failed");
        return -1;
    }

    if(task->syscall_state == 0){
        //printf("enter syscall 0x%llx\n",regs.orig_rax);
        if(enter_syscall_cb[regs.orig_rax]){
            enter_syscall_cb[regs.orig_rax](task->pid,&regs);
        }
    }else{
        //printf("return value : 0x%llx\n",regs.rax);
        if(leave_syscall_cb[regs.orig_rax]){
            leave_syscall_cb[regs.orig_rax](task->pid,&regs);
        }
    }
    task->syscall_state = (task->syscall_state + 1) & 1;
    return 0;
}

struct TaskCtx * wait_event(){
    //等待SIG_CHILD
    int statu = 0;
    int pid = waitpid(-1,&statu,0);

    if(pid < 0){
        perror("waitpid failed");
        exit(-1);
    }

    if(pid == 0){
        fprintf(stderr,"all child process exited!");
        exit(0);
    }

    struct TaskCtx * ctx = findTask(pid);

    if(!ctx){
        ctx = allocTaskCtx();
        int pos = allocTaskPos();

        if(pos < 0){
            fprintf(stderr,"No free task positon!");
            exit(-1);
        }

        ctx->pid = pid;
        ctx->pos = pos;
        ctx->syscall_state = 0;
        ctx->task_event = 0;

        tasks[pos] = ctx;
    }
    ctx->status = statu;

    //正常退出了.
    if(WIFEXITED(statu)){
        ctx->task_event = TE_EXIT;
        return ctx;
    }
    
    //异常退出，被信号杀死了.
    if(WIFSIGNALED(statu)){
        ctx->task_event = TE_EXIT;
        return ctx;
    }
    
    //程序暂停了.
    if(WIFSTOPPED(statu)){
        unsigned int event = statu >> 16;
        unsigned int signal = WSTOPSIG(statu);
        
        //printf("event: %d \n",event);

        switch (event)
        {
        case 0:
            if(signal == SYSCALL_TRAP){
                ctx->task_event = TE_SYSCALLTRAP;

            }else if(signal == SIGSTOP){
                ctx->task_event = TE_RESTART;

            }else{
                int stopped = ptrace(PTRACE_GETSIGINFO,
						pid, 0, &ctx->si) < 0;

                ctx->task_event = stopped ? TE_GROUP_STOP
							 : TE_SIGNAL_DELIVERY_STOP;          //是因为发送信号导致的暂停.
            }
            break;
        case PTRACE_EVENT_STOP:
            /*
                * PTRACE_INTERRUPT-stop or group-stop.
                * PTRACE_INTERRUPT-stop has sig == SIGTRAP here.
                */
            switch (signal) {
            case SIGSTOP:
            case SIGTSTP:
            case SIGTTIN:
            case SIGTTOU:
                ctx->task_event = TE_GROUP_STOP;
                break;
            default:
                ctx->task_event = TE_RESTART;
            }
            break;

        case PTRACE_EVENT_EXIT:
            ctx->task_event = TE_STOP_BEFORE_EXIT;
            break;

        case PTRACE_EVENT_EXEC:
            ctx->task_event = TE_STOP_BEFORE_EXECVE;
            break;

        case PTRACE_EVENT_CLONE:
        case PTRACE_EVENT_FORK:
        case PTRACE_EVENT_VFORK:
        default:
            ctx->task_event = TE_RESTART;
            break;
        }
    }
    return ctx;
}

void register_hook(){
    enter_syscall_cb[SYS_open] = enter_open_syscall;
    leave_syscall_cb[SYS_open] = leave_open_syscall;

    enter_syscall_cb[SYS_openat] = enter_open_syscall;
    leave_syscall_cb[SYS_openat] = leave_open_syscall;

    // enter_syscall_cb[SYS_execve] = enter_execve_syscall;
    leave_syscall_cb[SYS_read] = leave_read_syscall;
    leave_syscall_cb[SYS_write] = leave_write_syscall;
    // enter_syscall_cb[SYS_execveat] = enter_execve_syscall;
    // leave_syscall_cb[SYS_execveat] = leave_execve_syscall;


    //leave_syscall_cb[SYS_getdents] = leave_getdents_syscall;
    leave_syscall_cb[SYS_getdents64] = leave_getdents64_syscall;
}



/*



*/

int main(int argc,char * argv[],char * envp[]){
    int pid = 0,statu = 0;
    struct user_regs_struct regs;
    int loop = 0;

    if(argc <= 2){
        printf("Usage:%s [-l] prog args",argv[0]);
        exit(0);
    }
    if(!strcmp(argv[1],"-l")){
        loop = 1;
    }
    
    register_hook();

    do{
        //printf("fork\n");
        pid = fork();

        if(pid == 0){ 
            ptrace(PTRACE_TRACEME,0,0,0);
            //run program.
            execvp(argv[2],&argv[2]);
            perror("execve failed.");
            exit(-1);
        }

        //等待TRAP.
wait_exec:  
        if(waitpid(pid,&statu,0) < 0){
            perror("waitpid failed\n");
            exit(-1);
        }
        if(WIFEXITED(statu)){
            perror("tracee exit\n");
            exit(-1);
        }
        if(WIFSIGNALED(statu)){
            perror("tracee exit\n");
            exit(-1);
        }
        if(WSTOPSIG(statu) != SIGTRAP){
            goto wait_exec;
        }

        //
        if(ptrace(PTRACE_SETOPTIONS,pid,NULL,ptrace_setoptions) < 0){
            perror("ptrace setoptions failed!\n");
            exit(-1);
        }

        if (ptrace(PTRACE_SYSCALL,pid,0,0) < 0){
            perror("ptrace prog failed ");
            exit(-1);
        }
        
        while(1){
	    unsigned int restart_sig = 0;
            struct TaskCtx * ctx =  wait_event();
            if(!ctx){
                continue;
            }
            switch (ctx->task_event)
            {
            case TE_EXIT:                           //程序退出了.
remove_task:
                //printf("remove task[%d] ,pid: %d\n",ctx->pos,ctx->pid);
                tasks[ctx->pos] = NULL;
                free(ctx);
                break;

            case TE_SYSCALLTRAP:
                if(syscall_hook(ctx)){
                    goto remove_task;
                }
            case TE_STOP_BEFORE_EXECVE:
            case TE_STOP_BEFORE_EXIT:
            case TE_RESTART:
                //继续执行.
                if(ptrace(PTRACE_SYSCALL,ctx->pid,0,0) < 0){
                    perror("trace syscall failed");
                    goto remove_task;
                }
                break;

            case TE_GROUP_STOP:
            case TE_SIGNAL_DELIVERY_STOP:           //由信号导致的暂停.
                restart_sig = WSTOPSIG(ctx->status);
                //继续执行.
                if(ptrace(PTRACE_SYSCALL,ctx->pid,0,restart_sig) < 0){
                    perror("trace syscall failed");
                    goto remove_task;
                }
                break;
            default:
                fprintf(stderr,"Invalid Event\n");
                goto remove_task;
            }
        }
    }while(loop);
    return 0;
}
