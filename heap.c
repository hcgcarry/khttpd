

#define HEAP_CAPACITY 1024

#include <linux/module.h>
#include "content_cache_table.h"
#include <net/sock.h>
#include "heap.h"



extern atomic_t current_msec;
extern struct content_cache_table cache_table;
extern struct heap cache_heap;


void heap_print(struct heap* this){
    int heap_size = atomic_read(&this->heap_size);
    int i =0;
    printk("heap_size: %d",heap_size);
    for(;i<heap_size;i++){
        // struct cache_element* element = container_of(this->array[i],struct cache_element,list);
        printk("i:%d time:%d",i,this->array[i]->time);
    }
}

struct expire* heap_delete_expire_element(struct heap* this){
    printk("-----heap_delete_expire_element");

    spin_lock(&this->lock);
    int heap_size = atomic_read(&this->heap_size);
    printk("heap_size: %d",heap_size);
    printk(" current time %d", atomic_read(&current_msec));

    if(heap_size == 0 || this->array[0]->time > atomic_read(&current_msec)){
        spin_unlock(&this->lock);
        return NULL;
    }

    printk(" top time %d" ,this->array[0]->time);
    printk(" delete ");
    int cur_pos = 0;
    struct expire* last_element = this->array[heap_size-1];
    struct expire* expire_element = this->array[0];
    atomic_dec(&this->heap_size);
    heap_size = heap_size-1;
    this->array[0] = last_element;
    while(1){
        int parent;
        int parent1 = 2* cur_pos + 1;
        int parent2 = 2* cur_pos + 2;
        printk("cur_pos: %d",cur_pos);
        this->heap_print(this);
        if(parent1 < heap_size && parent2 < heap_size){
            if(this->array[parent1]->time <  this->array[parent2]->time){
                parent = parent1;
            }
            else{
                parent = parent2;
            }
           
        }
        else if(parent1 < heap_size){
            parent = parent1;
        }
        else if(parent2 < heap_size){
            parent = parent1;
        }
        else{
            break;
        }

        if(this->array[parent]->time < last_element->time){
            this->array[cur_pos] = this->array[parent];
            this->array[parent] = last_element;
            cur_pos = parent;
            continue;
        }
        break;
    }
    this->heap_print(this);
   
    
    spin_unlock(&this->lock);

    return expire_element;
}


void heap_insert_element(struct heap* this,struct cache_element* element){
    printk("-----heap_insert_element");
    spin_lock(&this->lock);

    int cur_pos = atomic_read(&this->heap_size);
    printk("cur_pos: %d",cur_pos);
    while(cur_pos>0){
        int parent = cur_pos/2;
        if(this->array[parent]->time > element->expire_time.time){
            this->array[cur_pos] = this->array[parent];
            cur_pos = parent;
        }
        else{
            break;
        }
        printk("cur_pos %d",cur_pos);
    }
    this->array[cur_pos] = &element->expire_time;
    atomic_inc(&this->heap_size);

    spin_unlock(&this->lock);

}

void timer_update_current_msec(void)
{
    printk("----- timer_update_current_msec");
    struct timespec64 tv;
    ktime_get_ts64(&tv);
    atomic_set(&current_msec, tv.tv_sec * 1000 + tv.tv_nsec / 1000000);
    printk("current time:%d",atomic_read(&current_msec));

    return;
}




int delete_timer_cache_deamon(void *arg)
{
    printk("----- delete_timer_cache_deamon");

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);


    while (!kthread_should_stop()) {
        msleep(10000);
        timer_update_current_msec();
        struct expire* expire_element = cache_heap.heap_delete_expire_element(&cache_heap);
        if(expire_element){
            struct cache_element* element = container_of(expire_element,struct cache_element,expire_time);
            printk(" has expire_element %d",element->expire_time.time);
            cache_table.delete_element(&cache_table,element);
        }
    }
    printk("----- delete_timer_cache_deamon unload");
  
    return 0;
}

void heap_init(struct heap* this){
    this->heap_delete_expire_element = heap_delete_expire_element;
    this->heap_insert_element = heap_insert_element;
    this->heap_print=heap_print;
}