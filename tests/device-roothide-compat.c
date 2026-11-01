// 在独立进程复现 launchd 的 XPC 接收 Hook，不注入系统服务或开启插件。
#include "libhooker.h"
#include <dlfcn.h>
#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <xpc/xpc.h>

extern xpc_object_t xpc_pipe_create_from_port(mach_port_t port, uint64_t flags);
extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t message, xpc_object_t *reply);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
extern int xpc_pipe_receive(mach_port_t port, xpc_object_t *message);

static int (*originalFunction)(int);
static int (*originalReceive)(void *, void *, void *, void *, xpc_object_t *);
static mach_port_t serverPort;
static int senderResult = -1, replyResult = -1;
static unsigned received;

// 保留可重定位的真实指令，并与 main 同处普通 Mach-O 代码页。
__attribute__((noinline,optnone)) static int testFunction(int value) { return value + 7; }

// 验证原函数跳板以及新入口均能执行。
static int replacementFunction(int value) { return originalFunction(value) + 100; }

// 模拟 launchd 消费私有请求后返回 EINVAL，使外层接收循环忽略此消息。
static int replacementReceive(void *msg, void *a2, void *a3, void *a4, xpc_object_t *out) {
    int result = originalReceive(msg, a2, a3, a4, out);
    if (!result && out && *out && xpc_dictionary_get_int64(*out, "lh-probe") == 41) {
        received++;
        xpc_object_t reply = xpc_dictionary_create_reply(*out);
        if (reply) {
            xpc_dictionary_set_int64(reply, "lh-probe", 42);
            replyResult = xpc_pipe_routine_reply(reply);
            xpc_release(reply);
        }
        xpc_release(*out);
        *out = NULL;
        return EINVAL;
    }
    return result;
}

// 发送真实同步 XPC 消息，检查 Hook 内处理的回复能够唤醒发送线程。
static void *sendRequest(void *context) {
    (void)context;
    xpc_object_t pipe = xpc_pipe_create_from_port(serverPort, 0);
    xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0), reply = NULL;
    xpc_dictionary_set_int64(request, "lh-probe", 41);
    senderResult = xpc_pipe_routine(pipe, request, &reply);
    if (!senderResult && (!reply || xpc_dictionary_get_int64(reply, "lh-probe") != 42)) senderResult = EPROTO;
    if (reply) xpc_release(reply);
    xpc_release(request);
    xpc_release(pipe);
    return NULL;
}

// 对指定引擎执行 Mach-O 同页 Hook 和共享缓存 XPC 请求往返，失败时返回非零。
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    if (argc != 2) return 2;
    alarm(15);
    printf("backend exports: protect=%p patch=%p\n", dlsym(RTLD_DEFAULT, "substrate_vm_protect"),
        dlsym(RTLD_DEFAULT, "substrate_hook_memory"));
    void *engine = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    if (!engine) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    int (*hookFunctions)(const struct LHFunctionHook *, int) = dlsym(engine, "LHHookFunctions");
    void (*hookFunction)(void *, void *, void **) = dlsym(engine, "MSHookFunction");
    if (!hookFunctions || !hookFunction) return 2;
    struct LHFunctionHook hook = {(void *)testFunction, (void *)replacementFunction, &originalFunction, NULL};
    int installed = hookFunctions(&hook, 1), error = errno;
    int (*volatile call)(int) = testFunction;
    int value = call(5);
    printf("Mach-O Hook: count=%d errno=%d original=%p value=%d\n", installed, error, originalFunction, value);
    if (installed != 1 || !originalFunction || value != 112 || originalFunction(5) != 12) return 1;
    void *receive = dlsym(RTLD_DEFAULT, "xpc_receive_mach_msg");
    if (!receive) return 2;
    hookFunction(receive, replacementReceive, (void **)&originalReceive);
    if (!originalReceive) { fprintf(stderr, "XPC Hook failed: errno=%d\n", errno); return 1; }
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort) != KERN_SUCCESS ||
        mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) return 2;
    pthread_t sender;
    if (pthread_create(&sender, NULL, sendRequest, NULL)) return 2;
    xpc_object_t message = NULL;
    int result = xpc_pipe_receive(serverPort, &message);
    pthread_join(sender, NULL);
    if (message) xpc_release(message);
    mach_port_mod_refs(mach_task_self(), serverPort, MACH_PORT_RIGHT_RECEIVE, -1);
    mach_port_deallocate(mach_task_self(), serverPort);
    printf("XPC Hook: receive=%d hits=%u reply=%d sender=%d\n", result, received, replyResult, senderResult);
    // xpc_pipe_receive 可把内部 EINVAL 转成 EIO；launchd 的契约是不能返回成功。
    return result != 0 && received == 1 && replyResult == 0 && senderResult == 0 ? 0 : 1;
}
