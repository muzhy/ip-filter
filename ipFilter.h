#ifndef __IP_FILTER_H__
#define __IP_FILTER_H__

#include <stdint.h>

// if_node ip_filter_node
typedef struct if_node{
    // ip address as bit array, the ip address sub 
    // bit array(pos, len) should equal value
    int32_t value;          
    int8_t pos;             
    int8_t len;
    if_node* next_zero;     // next bit is zero
    if_node* next_one;      // next bit is one
}if_node;

if_node* create_if_node();          
void destory_if_tree(if_node* root);     
bool add_pass_ip(if_node* root, int32_t ip);                    
bool add_pass_mask(if_node* root, int32_t mask, int mask_len);  
bool add_pass_section(if_node* root, char* str_section);        
bool check_ip(if_node* filter_root, int32_t ip);                


#endif // __IP_FILTER_H__