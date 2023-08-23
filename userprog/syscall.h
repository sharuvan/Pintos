#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

// map file structures and descriptors
struct file_map
{
    struct list_elem elem; /* List element*/
    int fd;                /* File descriptor. */
    struct file *file;     /* File structure. */
};

void syscall_init(void);
bool valid_buffer(void *buffer, size_t length);
bool valid_string(const char *str);
bool sys_create(const char *name, unsigned int initial_size);
bool sys_remove(const char *file);
void sys_halt (void);
void sys_exit (int status);
void sys_seek (int fd, unsigned position);
void sys_close (int fd);
int sys_write(int fd, const void *buffer, unsigned int length);

#endif /* userprog/syscall.h */
