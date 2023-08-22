#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

// map file structures and descriptors
struct file_map{
    struct list_elem elem;      /* List element*/
    int fd;                     /* File descriptor. */
    struct file *file;          /* File structure. */
};

bool valid_buffer (void *buffer, size_t length);
void sys_exit (int status);
int sys_write (int fd, const void *buffer, unsigned int length);
void syscall_init (void);

#endif /* userprog/syscall.h */
