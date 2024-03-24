

#ifndef KHTTPD_HEAP
#define KHTTPD_HEAP

#define HEAP_CAPACITY 1024

#include <linux/module.h>
#include <net/sock.h>



extern atomic_t current_msec;
extern struct content_cache_table cache_table;
extern struct heap cache_heap;



struct heap{
    struct expire* array[HEAP_CAPACITY];
    atomic_t heap_size;
    spinlock_t lock;
    struct expire* (*heap_delete_expire_element)(struct heap* );
    void (*heap_insert_element)(struct heap* ,struct cache_element* );
    void (*heap_init)(struct heap*);
};


struct expire* heap_delete_expire_element(struct heap* this);

void heap_init(struct heap* this);

void heap_insert_element(struct heap* this,struct cache_element* element);

void timer_update_current_msec(void);

int delete_timer_cache_deamon(void *arg);

#endif