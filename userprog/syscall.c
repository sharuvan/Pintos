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
  case SYS_HALT:
      sys_halt();
      break;
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

  case SYS_SEEK:
    sys_seek ((int) load_stack (frame, POS0),
      (unsigned) load_stack (frame, POS1));
    break;
  
  case SYS_CLOSE:
    sys_close ((int) load_stack (frame, POS0));
    break;

  default:
    sys_exit(EXIT_ERROR_CODE);
    break;
  }
}

// get file map from file descriptor
struct file_map * get_file_map(int fd) {
  struct thread *ct = thread_current ();
  struct list_elem *element;
  struct file_map *fileMap;

  for (element = list_begin (&ct->fileList); element != list_end (&ct->fileList);
  	element = list_next (element)) {
    fileMap = list_entry (element, struct file_map, elem);
    if (fileMap->fd == fd) return fileMap;
  }
  return NULL;
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

// read a byte from user memory space
static int read_user (const uint8_t *address) {
  if ((uint32_t) address >= (uint32_t) PHYS_BASE) return -1;
  int res;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (res) : "m" (*address));
  return res;
}

// write a byte to user memory space
static bool write_user (uint8_t *address, uint8_t byte) {
  if ((uint32_t) address < (uint32_t) PHYS_BASE) return false;
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*address) : "q" (byte));
  return error_code != -1;
}

// validate and dereference stack pointer
static uint32_t load_stack (struct intr_frame *frame, int offset) {
  if (!valid_usr_ptr (frame->esp + offset)) sys_exit (EXIT_ERROR_CODE);
  return *((uint32_t *) (frame->esp + offset));
}

// check if valid user pointer
bool valid_usr_ptr (void *vaddr) {
  return read_user((uint8_t *)vaddr) != -1;
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

// shutdown
void sys_halt (void) {
  shutdown_power_off ();
}

// terminate process with exitcode
void sys_exit(int status)
{
  struct thread *ct = thread_current();
  ct->exitcode = status;
  thread_exit();
}

// wait for process to end
int sys_wait (pid_t pid) {
  return process_wait (pid);
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

// open file
int sys_open (const char *file) {
  if (!valid_string (file)) sys_exit (EXIT_ERROR_CODE);

  int fd = MINIMUM_FD;
  struct file_map *fileMap;
  struct thread *ct = thread_current ();

  while (fd >= MINIMUM_FD && get_file_map (fd) != NULL) fd++;
  if (fd < MINIMUM_FD) sys_exit (EXIT_ERROR_CODE);
  fileMap = malloc (sizeof (struct file_map));
  if (fileMap == NULL) return -1;
  fileMap->fd = fd;
  sema_down (&sema);
  fileMap->file = filesys_open (file);
  sema_up (&sema);

  if (fileMap->file == NULL){
      free (fileMap);
      return -1;
  }
  list_push_back (&ct->fileList, &fileMap->elem);

  return fileMap->fd;
}

// fetch file size from descriptor
int sys_filesize(int fd) {
  struct file_map *fileMap = get_file_map(fd);
  if (fileMap == NULL) return -1;
  sema_down(&sema);
  int size = file_length(fileMap->file);
  sema_up(&sema);
  return size;
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

// seek file position
void sys_seek (int fd, unsigned position) {
  struct file_map *fileMap = get_file_map (fd);
  if (fileMap == NULL) return;
  sema_down (&sema);
  file_seek (fileMap->file, position);
  sema_up (&sema);
}

// close file
void sys_close (int fd) {
  struct file_map *fileMap = get_file_map (fd);
  if (fileMap == NULL)  return;
  sema_down (&sema);
  file_close (fileMap->file);
  sema_up (&sema);
  list_remove (&fileMap->elem);
  free (fileMap);
}