//
//  Demo: Anti Anti-Debug in iOS Kernel
//  Created by Proteas on 2017/11/29.
//

#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>

extern "C" {

// external function
extern int proc_pid(struct proc *);
extern void proc_name(int, char *, int);
extern int proc_is64bit(struct proc *);
extern vm_offset_t ml_io_map( vm_offset_t phys_addr, vm_size_t size);

// external types
#if CONFIG_REQUIRES_U32_MUNGING
    #define PAD_(t) (sizeof(uint64_t) <= sizeof(t) ? 0 : sizeof(uint64_t) - sizeof(t))
#else
    #define PAD_(t) (sizeof(uint32_t) <= sizeof(t) ? 0 : sizeof(uint32_t) - sizeof(t))
#endif /* CONFIG_REQUIRES_U32_MUNGING */

#if BYTE_ORDER == LITTLE_ENDIAN
    #define PADL_(t) 0
    #define PADR_(t) PAD_(t)
#else
    #define PADL_(t) PAD_(t)
    #define PADR_(t) 0
#endif

// ptrace_args
struct ptrace_args {
    char req_l_[PADL_(int)]; int req; char req_r_[PADR_(int)];
    char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
    char addr_l_[PADL_(user_addr_t)]; user_addr_t addr; char addr_r_[PADR_(user_addr_t)];
    char data_l_[PADL_(int)]; int data; char data_r_[PADR_(int)];
};

// sysctl_args
struct sysctl_args {
    char name_l_[PADL_(user_addr_t)]; user_addr_t name; char name_r_[PADR_(user_addr_t)];
    char namelen_l_[PADL_(u_int)]; u_int namelen; char namelen_r_[PADR_(u_int)];
    char old_l_[PADL_(user_addr_t)]; user_addr_t old; char old_r_[PADR_(user_addr_t)];
    char oldlenp_l_[PADL_(user_addr_t)]; user_addr_t oldlenp; char oldlenp_r_[PADR_(user_addr_t)];
    char new_l_[PADL_(user_addr_t)]; user_addr_t new_a; char new_r_[PADR_(user_addr_t)];
    char newlen_l_[PADL_(user_size_t)]; user_size_t newlen; char newlen_r_[PADR_(user_size_t)];
};

// user64_time_t
typedef int64_t user64_time_t __attribute__((aligned(8)));

// user64_timeval
struct user64_timeval {
    user64_time_t tv_sec;
    int tv_usec;
};

// user64_extern_proc
struct user64_extern_proc {
    union {
        struct {
            uint64_t __p_forw;
            uint64_t __p_back;
        } p_st1;
        struct user64_timeval __p_starttime;
    } p_un;
    uint64_t p_vmspace;
    uint64_t p_sigacts;
    int p_flag;
};

// user64_kinfo_proc
struct user64_kinfo_proc {
    struct user64_extern_proc kp_proc;
};

} /* extern "C" */
/*******************************************************************************/

extern "C" {

// depends on device and os ver
static uint64_t gOffsetPtrace = 0x00000000004fa350;
static uint64_t gOffsetSysctl = 0x00000000004fb3d0;
static vm_offset_t gKernPhyAddr = 0x800C04000;
static vm_size_t gKernMapSize = 0x600000; // far enough for hook
/*******************************************************************************/

// function ptr type
typedef int (*ptrace_t)(struct proc *, struct ptrace_args *, int *);
typedef int (*sysctl_t)(struct proc *, struct sysctl_args *, int *);

// original function address
static ptrace_t g_orig_ptrace = NULL;
static sysctl_t g_orig_sysctl = NULL;
/*******************************************************************************/

// ptrs_ptrace
static int ptrs_ptrace(struct proc *p, struct ptrace_args *uap, int *retv)
{
#define PT_ATTACH       10
#define PT_DENY_ATTACH  31
#define SIGSEGV         11

    int pid = proc_pid(p);
    char procName[32] = {0};
    if(uap->req == PT_DENY_ATTACH) {
        proc_name(pid, procName, sizeof(procName));
        IOLog("[PRTS][KAADBG] anti ptrace: %d, %s\n", pid, procName);
        return 0;
    }
    
    return g_orig_ptrace(p, uap, retv);
}
/*******************************************************************************/

// ptrs_sysctl
static int ptrs_sysctl(struct proc *p, struct sysctl_args *uap, int *retv)
{
#define CTL_KERN      1
#define KERN_PROC     14
#define KERN_PROC_PID 1
#define P_TRACED      0x00000800

    int mib[4] = {0};
    char procName[32] = {0};
    int err = 0;
    pid_t pid = proc_pid(p);
    int ret = g_orig_sysctl(p, uap, retv);
    proc_name(pid, procName, sizeof(procName));

    if (strcmp(procName, "debugserver") == 0) {
        return ret;
    }

    err = copyin(uap->name, &mib, sizeof(mib));
    if (err != 0){
        IOLog("[PRTS][KAADBG] sysctl: copyin fail: %d\n", err);
        return ret;
    }
    
    if((mib[0] == CTL_KERN && mib[1] == KERN_PROC && mib[2] == KERN_PROC_PID) &&
       (uap->old != 0) && (proc_is64bit(p) == 1)) {
        IOLog("[PRTS][KAADBG] anti sysctl - QUERY: %d, %s\n", pid, procName);

        static const size_t bufSize = 648;
        char buf[bufSize] = {0};
        struct user64_kinfo_proc *kpr = (struct user64_kinfo_proc *)buf;
        err = copyin(uap->old, buf, bufSize); IOSleep(100);
        if (err != 0 ){
            IOLog("[PRTS][KAADBG] sysctl: copyin fail: %d\n", err);
            return ret;
        }

        if ((kpr->kp_proc.p_flag & P_TRACED) != 0) {
            kpr->kp_proc.p_flag ^= P_TRACED;
            err = copyout(buf, uap->old, bufSize); IOSleep(100);
            if (err != 0){
                IOLog("[PRTS][KAADBG] sysctl: copyout fail: %d\n", err);
                return ret;
            }
            IOLog("[PRTS][KAADBG] anti sysctl - ^P_TRACED: %d, %s\n", pid, procName);
        }
    }
    
    return ret;
}
/*******************************************************************************/

} /* extern "C" */
/*******************************************************************************/

// class: PRTS_KAADBG
class PRTS_KAADBG : public IOService
{
    OSDeclareDefaultStructors(PRTS_KAADBG)
    
public:
    virtual bool start (IOService *provider) APPLE_KEXT_OVERRIDE
    {
        if (IOService::start(provider) == false) {
            return false;
        }
        
        this->registerService();

        // map kernel
        vm_offset_t gKernelBaseRemapped = ml_io_map(gKernPhyAddr, gKernMapSize);

        // offset to position
        uint64_t *ptracePtr = (uint64_t *)(gKernelBaseRemapped + gOffsetPtrace);
        uint64_t *sysctlPtr = (uint64_t *)(gKernelBaseRemapped + gOffsetSysctl);

        // save original function address
        g_orig_ptrace = (ptrace_t)(*ptracePtr);
        g_orig_sysctl = (sysctl_t)(*sysctlPtr);

        // hook
        *ptracePtr = (uint64_t)ptrs_ptrace;
        *sysctlPtr = (uint64_t)ptrs_sysctl;

        IOLog("[PRTS][KAADBG] success to hook ptrace and sysctl\n");
        
        return true;
    }

    virtual void free (void) APPLE_KEXT_OVERRIDE
    {
        IOService::free();
    }
};
/*******************************************************************************/

OSDefineMetaClassAndStructors(PRTS_KAADBG, IOService)
/*******************************************************************************/
