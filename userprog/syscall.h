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
static void syscall_handler (struct intr_frame *f);
static int read_user (const uint8_t *uaddr);
static bool write_user (uint8_t *udst, uint8_t byte);
static uint32_t load_stack (struct intr_frame *f, int);
bool valid_usr_ptr (void *);
bool valid_buffer(void *buffer, size_t length);
bool valid_string(const char *str);
bool sys_create(const char *name, unsigned int initial_size);
bool sys_remove(const char *file);
void sys_halt (void);
void sys_exit (int status);
void sys_seek (int fd, unsigned position);
void sys_close (int fd);
int sys_wait (pid_t pid);
int sys_open (const char *file);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned length);
int sys_write(int fd, const void *buffer, unsigned int length);
unsigned sys_tell (int fd);
pid_t sys_exec (const char *cmd_line);
struct file_map *get_file_map (int fd);

#endif /* userprog/syscall.h */
