
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include "beaengine/BeaEngine.h"
#include "buddy.h"

#define jmp_14_bytes 0
#if jmp_14_bytes
#define retaddr_offset 24
#define retaddr_t uint64_t
#else
#define retaddr_offset 19
#define retaddr_t uint32_t
#endif

static struct buddy2* buddy = NULL;
static char buf[192 * 1024] __attribute__((aligned(4096)));

__attribute__((constructor))
static void init()
{
    buddy = buddy2_new(1024);
    mprotect(buf, sizeof(buf), PROT_READ | PROT_WRITE | PROT_EXEC);
}

static char* code_mem_alloc()
{
    int offset = buddy2_alloc(buddy, 1);
    if (offset == -1) {
        return NULL;
    }
    char* pch = &buf[192 * offset];
    *(uint16_t *) &pch[0] = 0x25ff;
    return pch;
}

static void code_mem_free(char* pch)
{
    int offset = (pch - buf) / 128;
    buddy2_free(buddy, offset);
}

typedef struct {
    void* rdi;
    void* rsi;
    void* rdx;
    void* rcx;
    void* r8;
    void* r9;
    void* rsp;
    void* rbp;
    void* ret;
    void* rsp2;
    void* rbp2;
    int idx1, idx2, idx3;
    char* jmp;

    void* target;
    void* mine;

    intptr_t shadow;
    void (*forward) (void*, intptr_t);
    void (*end) (void* hook, intptr_t n);
} hook_t;

static int jump_to(char* jmp, intptr_t addr)
{
#if jmp_14_bytes
    *(uint16_t *) &jmp[0] = 0x25ff;
    *(uint32_t *) &jmp[2] = 0x00000000;
    *(uint64_t *) &jmp[6] = (uint64_t) addr;
    return 14;
#else
    *(uint8_t *) &jmp[0] = 0x68;
    *(uint32_t *) &jmp[1] = (uint32_t) addr;
    *(uint8_t *) &jmp[5] = 0xc3;
    return 6;
#endif
}

static int le(void* func)
{
    DISASM infos;
    int len = 0;
    (void) memset (&infos, 0, sizeof(DISASM));
    infos.EIP = (UInt64) func;
    printf("%p\n", func);

    while ((infos.Error == 0) && len < 14) {
        int nb = Disasm(&infos);
        printf("%s\n", infos.CompleteInstr);
        if (infos.Error == UNKNOWN_OPCODE || infos.Instruction.Opcode == 0xc3) {
            return -1;
        }
        infos.EIP += nb;
        len += nb;
    }
    return len;
}

static int x86_64_jmp_init(hook_t* hook)
{
    int nb = le(hook->target);
    if (nb == -1) {
        return -1;
    }

    int n = 0;
    *(uint16_t *) &hook->jmp[n] = 0xba49;
    n += sizeof(uint16_t);
    *(uint64_t *) &hook->jmp[n] = (uint64_t) hook;
    n += sizeof(uint64_t);

    *(uint16_t *) &hook->jmp[n] = 0x8949;
    n += sizeof(uint16_t);
    *(uint8_t *) &hook->jmp[n] = 0x3a;
    n += sizeof(uint8_t);

    *(uint16_t *) &hook->jmp[n] = 0x8949;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x0872;
    n += sizeof(uint16_t);

    *(uint16_t *) &hook->jmp[n] = 0x8949;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x1052;
    n += sizeof(uint16_t);

    *(uint16_t *) &hook->jmp[n] = 0x8949;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x184a;
    n += sizeof(uint16_t);

    *(uint16_t *) &hook->jmp[n] = 0x894d;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x2042;
    n += sizeof(uint16_t);

    *(uint16_t *) &hook->jmp[n] = 0x894d;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x284a;
    n += sizeof(uint16_t);

    *(uint16_t *) &hook->jmp[n] = 0x8949;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x3062;
    n += sizeof(uint16_t);

    *(uint16_t *) &hook->jmp[n] = 0x8949;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x386a;
    n += sizeof(uint16_t);
    n += jump_to(&hook->jmp[n], (intptr_t) hook->mine);
    hook->idx1 = n;

    *(uint16_t *) &hook->jmp[n] = 0xba49;
    n += sizeof(uint16_t);
    *(uint64_t *) &hook->jmp[n] = (uint64_t) hook;
    n += sizeof(uint64_t);

    *(uint16_t *) &hook->jmp[n] = 0x8b49;
    n += sizeof(uint16_t);
    *(uint8_t *) &hook->jmp[n] = 0x3a;
    n += sizeof(uint8_t);

    *(uint16_t *) &hook->jmp[n] = 0x8b49;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x0872;
    n += sizeof(uint16_t);

    *(uint16_t *) &hook->jmp[n] = 0x8b49;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x1052;
    n += sizeof(uint16_t);

    *(uint16_t *) &hook->jmp[n] = 0x8b49;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x184a;
    n += sizeof(uint16_t);

    *(uint16_t *) &hook->jmp[n] = 0x8b4d;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x2042;
    n += sizeof(uint16_t);

    *(uint16_t *) &hook->jmp[n] = 0x8b4d;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x284a;
    n += sizeof(uint16_t);

    *(uint16_t *) &hook->jmp[n] = 0x8b49;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x3062;
    n += sizeof(uint16_t);

    *(uint16_t *) &hook->jmp[n] = 0x8b49;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x386a;
    n += sizeof(uint16_t);

    memcpy(&hook->jmp[n], hook->target, nb);
    n += nb;
    // jmp to left of func
    n += jump_to(&hook->jmp[n], (intptr_t) (hook->target) + nb);
    hook->idx2 = n;

    // restore rsp2, rbp2 to %rsp, %rbp
    // then jump back
    *(uint16_t *) &hook->jmp[n] = 0xba49;
    n += sizeof(uint16_t);
    *(uint64_t *) &hook->jmp[n] = (uint64_t) hook;
    n += sizeof(uint64_t);

    *(uint16_t *) &hook->jmp[n] = 0x8b49;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x4862;
    n += sizeof(uint16_t);

    *(uint16_t *) &hook->jmp[n] = 0x8b49;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x506a;
    n += sizeof(uint16_t);
    n += jump_to(&hook->jmp[n], 0);
    hook->idx3 = n;

    *(uint16_t *) &hook->jmp[n] = 0xba49;
    n += sizeof(uint16_t);
    *(uint64_t *) &hook->jmp[n] = (uint64_t) hook;
    n += sizeof(uint64_t);

    *(uint16_t *) &hook->jmp[n] = 0x8b49;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x3062;
    n += sizeof(uint16_t);

    *(uint16_t *) &hook->jmp[n] = 0x8b49;
    n += sizeof(uint16_t);
    *(uint16_t *) &hook->jmp[n] = 0x386a;
    n += sizeof(uint16_t);
    *(uint64_t *) &hook->jmp[n] = 0x4062ff41;
    n += 8;
    return n;
}

static void forward_call(hook_t* hook, intptr_t shadow)
{
    char* addr = NULL;
    if (shadow != 0) {
        hook->shadow = shadow;
        addr = &hook->jmp[hook->idx2];
        retaddr_t* intp = (retaddr_t *) &addr[retaddr_offset];
        intp[0] = (retaddr_t) (__builtin_return_address(0));
        void** ret = (void **) hook->rsp;
        hook->ret = *ret;
        *ret = addr;
    }

    addr = &hook->jmp[hook->idx1];
    __asm__ __volatile__("jmp *%0" ::"m"(addr));
}

__asm__ (
    ".align 16\n"
    ".type forward,@function\n"
    "forward:\n"
    "    lea  -8(%rsp), %rax\n"
    "    movq  %rax, 72(%rdi)\n"
    "    movq  %rbp, 80(%rdi)\n"
    "    jmp  forward_call\n"
    "    hlt\n"
    ".size forward,.-forward"
);
static void forward(void* ptr, intptr_t shadow);

static void end(hook_t* hook, intptr_t n)
{
    char* addr = &hook->jmp[hook->idx3];
    __asm__ __volatile__("movq (%0), %%rax\njmp *%1" ::"r"(&n), "m"(addr));
}

static int code_protect(void* func, int size, int attr)
{
    int pagesize = getpagesize();
#define PAGE_START(x, pagesize) ((x) & ~((pagesize) - 1))
    size_t start = (size_t) PAGE_START((long) func, pagesize);
    size_t n = 1 + ((size_t) func + size > start + pagesize);
#undef PAGE_START
    return mprotect((void *) start, (size_t) pagesize * n, attr);
}

hook_t* hook_init(void* target, void* mine)
{
    hook_t* hook = malloc(sizeof(*hook));
    hook->target = target;
    hook->mine = mine;
    hook->forward = forward;
    hook->end = (typeof(hook->end)) end;
    hook->jmp = code_mem_alloc();

    int n = x86_64_jmp_init(hook);
    if (n != -1) {
        n = code_protect(hook->target, 14, PROT_READ | PROT_WRITE | PROT_EXEC);
    }

    if (n == -1) {
        code_mem_free(hook->jmp);
        free(hook);
        return NULL;
    }
    jump_to((char *) hook->target, (intptr_t) hook->jmp);
    code_protect(hook->target, 14, PROT_READ | PROT_EXEC);
    return hook;
}

hook_t* hook_get()
{
     hook_t* hook = NULL;
     __asm__ __volatile__("movq %%r10, %0\n" :"=m"(hook) ::);
     return hook;
}

void my_connect(int n)
{
    hook_t* hook = hook_get();
    int** shadow = (int **) malloc(sizeof(int*));
    printf("%s: %d %p\n", __func__, __LINE__, __builtin_return_address(1));

    int (*fptr) (void*, intptr_t) = (typeof(fptr)) hook->forward;
    n = fptr(hook, NULL);

    hook = hook_get();
    shadow = (int **) hook->shadow;

    printf("I am back %d\n", n);
    free(shadow);
    hook->end(hook, n);
}

static void a()
{
    __asm__("pushq $12345678\n retq");
}

static void f(int n)
{
    printf("hello world\n");
}

int main() {
    int n = dup(0);
   // hook_init(dup, my_connect);
   // hook_init(close, my_connect);
    void* a = NULL;

    printf("%d %p %p\n", n, dup, close);

    return 0;
    __asm__ __volatile__("push _exit@PLT");

    printf("---------------------------%p:%p\n", a, close);
   // printf("%p\n", close@plt);
    //f(1);

     n = dup(0);
    return printf("%d\n", n);
}
