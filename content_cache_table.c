
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include "content_cache_table.h"





int string_to_hash(char* key){
    int hash = 0;
    while(*key){
        hash += *key;
        hash %= CONTENT_CACHE_TABLE_SIZE;
        key++;
    }
    return hash;
}


struct list_head* getBuckets(struct content_cache_table* this, char* key){
    int hash = string_to_hash(key);
    printk("hash %d",hash);
    return &this->buckets[hash];
}


struct cache_element* cache_element_init(char*key){
    struct cache_element* element = (struct cache_element*) kmalloc(sizeof(struct cache_element),GFP_KERNEL);
    element->key = (char*) kmalloc(strlen(key),GFP_KERNEL);
    strcpy(element->key,key);
    element->content = NULL;
    element->content_len = 0;
    return element;
}


void insert_element(struct content_cache_table* this,struct cache_element* element){
    printk("----insert_element ");
    spin_lock(&this->lock);
    struct list_head* buckets = getBuckets(this,element->key);
    list_add(&element->list,buckets);
    spin_unlock(&this->lock);
}

char* get_element(struct content_cache_table* this,char* key){
    printk("----get_element");
    char* content = NULL;
    struct list_head* buckets = getBuckets(this,key);
    struct cache_element* cur_element = NULL;

    rcu_read_lock();
    list_for_each_entry_rcu(cur_element,buckets,list){
        if(strcmp(cur_element->key,key) == 0){
            printk("match key");
            printk("content_len %d",cur_element->content_len);
            printk("strlen content_len %d",strlen(cur_element->content));
            printk("content %s",cur_element->content);
            content = (char*)kmalloc(cur_element->content_len + 1,GFP_KERNEL);
            strcpy(content,cur_element->content);
            break;
        }
    }
    rcu_read_unlock();
    return content;
}




void content_cache_table_init(struct content_cache_table* this){
    int i = 0;
    this->get_element = get_element;
    this->getBuckets = getBuckets;
    this->insert_element = insert_element;
    for(i=0;i<CONTENT_CACHE_TABLE_SIZE;i++){
        INIT_LIST_HEAD(&this->buckets[i]);
    }
}