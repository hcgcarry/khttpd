
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/fs.h>

#ifndef KHTTPD_CONTENT_CACHE_TABLE
#define KHTTPD_CONTENT_CACHE_TABLE


#define CONTENT_CACHE_TABLE_SIZE 1024

struct cache_element{
    char *key;
    struct list_head list;
    char* content;
    int content_len;
    struct dir_context dir;
};



struct content_cache_table{
    spinlock_t lock;
    struct list_head buckets[CONTENT_CACHE_TABLE_SIZE];
    struct list_head* (*getBuckets)(struct content_cache_table* ,char*);
    void (*insert_element)(struct content_cache_table* ,struct cache_element* );
    char* (*get_element)(struct content_cache_table* ,char*);

};


void content_cache_table_init(struct content_cache_table* this);

struct cache_element* cache_element_init(char*key);

int string_to_hash(char* key);

struct list_head* getBuckets(struct content_cache_table* this, char* key);
void insert_element(struct content_cache_table* this,struct cache_element* element);
char* get_element(struct content_cache_table* this,char* key);


#endif 





