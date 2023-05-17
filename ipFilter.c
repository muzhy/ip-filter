#include "ipFilter.h"

#include <stdlib.h>

if_node* create_if_node(){
    if_node* node = (if_node*) malloc(sizeof(if_node));
    return node;
}

void destory_if_tree(if_node* root){
    if(root == NULL){ return ;}

    if(root->next_zero != NULL){
        destory_if_tree(root->next_zero);
    }

    if(root->next_one != NULL){
        destory_if_tree(root->next_one);
    }

    free(root);
    root = NULL;

    return ;
}

bool add_pass_ip(if_node* root, int32_t ip){
    if(root == NULL){
        return false;
    }
    
}