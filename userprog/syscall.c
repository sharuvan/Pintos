#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

#define POS0 4
#define POS1 8
#define POS2 12
#define MINIMUM_FD 2
#define MAXIMUM_BUFFER 512
#define EXIT_ERROR_CODE -1

static struct semaphore sema;

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  sema_init(&sema, 1);
}

static void syscall_handler(struct intr_frame *frame)
{
  int call = (int)load_stack(frame, 0);

  switch (call)
  {
  case SYS_EXIT:
    sys_exit((int)load_stack(frame, POS0));
    break;

  case SYS_CREATE:
    frame->eax = sys_create((const char *)load_stack(frame, POS0),
                            (unsigned int)load_stack(frame, POS1));
    break;

  case SYS_REMOVE:
    frame->eax = sys_remove((const char *)load_stack(frame, POS0));
    break;

  case SYS_WRITE:
    frame->eax = sys_write((int)load_stack(frame, POS0),
                           (const void *)load_stack(frame, POS1),
                           (unsigned int)load_stack(frame, POS2));
    break;

  default:
    sys_exit(EXIT_ERROR_CODE);
    break;
  }
}

// get file map from file descriptor
struct file_map *get_file_map(int fd)
{
  struct thread *ct = thread_current();
  struct list_elem *element;
  struct file_map *fileMap;

  for (element = list_begin(&ct->fileList); element != list_end(&ct->fileList);
       element = list_next(element))
  {
    fileMap = list_entry(element, struct file_map, elem);
    if (fileMap->fd == fd)
      return fileMap;
  }
  return NULL;
}

// check if valid buffer
bool valid_buffer(void *buffer, size_t length)
{
  char *buffer_char = (char *)buffer;
  for (size_t i = 0; i < length; i++)
    if (!valid_usr_ptr(buffer_char + i))
      return false;
  return true;
}

// check if valid string
bool valid_string(const char *str)
{
  for (size_t i = 0;; i++)
  {
    if (!valid_usr_ptr((void *)(str + i)))
      return false;
    if (read_user((uint8_t *)(str + i)) == '\0')
      return true;
  }
}

// terminate process with exitcode
void sys_exit(int status)
{
  struct thread *ct = thread_current();
  ct->exitcode = status;
  thread_exit();
}

// create file
bool sys_create(const char *name, unsigned int initial_size)
{
  if (!valid_string(name))
    sys_exit(EXIT_ERROR_CODE);
  sema_down(&sema);
  bool success = filesys_create(name, initial_size);
  sema_up(&sema);
  return success;
}

// delete file
bool sys_remove(const char *file)
{
  if (!valid_string(file))
    sys_exit(EXIT_ERROR_CODE);
  sema_down(&sema);
  bool success = filesys_remove(file);
  sema_up(&sema);
  return success;
}

// buffered file write
int sys_write(int fd, const void *buffer, unsigned int length)
{
  struct file_map *fileMap;
  unsigned int len;
  char *buffer_char;

  if (!valid_buffer((void *)buffer, length))
    sys_exit(EXIT_ERROR_CODE);

  if (fd == STDOUT_FILENO)
  {
    len = length;
    buffer_char = (char *)buffer;

    while (len > MAXIMUM_BUFFER)
    {
      putbuf((const char *)buffer_char, MAXIMUM_BUFFER);
      len -= MAXIMUM_BUFFER;
      buffer_char += MAXIMUM_BUFFER;
    }
    putbuf((const char *)buffer_char, len);
    return length;
  }
  fileMap = get_file_map(fd);
  if (fileMap == NULL)
    sys_exit(EXIT_ERROR_CODE);
  sema_down(&sema);
  int return_val = file_write(fileMap->file, buffer, length);
  sema_up(&sema);

  return return_val;
}
