#include <assert.h>
#include <stddef.h>
#include <stdint.h>

// TBD:
extern void *__fw_malloc(size_t n);
extern void __fw_free(void *p);
extern uint32_t __fw_rdrand32(void);
extern void *__fw_realloc(void *p, size_t n);

void *malloc(size_t n)
{
    return __fw_malloc(n);
}

void free(void *p)
{
    __fw_free(p);
}

void *realloc(void *p, size_t n)
{
    if(n == 0) {
        return NULL;
    }

    if (p == NULL)
    {
       return malloc(n); 
    }
        
    return __fw_realloc(p,n); 
}

int rand(void)
{
    return (int)__fw_rdrand32();
}
