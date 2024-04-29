#ifndef _cpu_h_
#define _cpu_h_

// A file for code that manipulates CPU functionality.

#if defined(CONFIG_DUAL_CORE)
struct busy_wait
{
    uint32_t waiting; // signals to caller that we're busy-waiting
    uint32_t wake; // signals to callee to stop waiting
};

void busy_wait_cpu1(void *wait);
void suspend_cpu1(void);
int wait_for_cpu1_to_suspend(int32_t timeout);
#endif // CONFIG_DUAL_CORE

#endif // _cpu_h_
