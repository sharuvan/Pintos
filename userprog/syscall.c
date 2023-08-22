#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#define POS0 4
#define POS1 8
#define POS2 12
#define EXIT_ERROR_CODE -1

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void syscall_handler (struct intr_frame *frame) {
  int call = (int) load_stack (frame, 0);

  switch (call)
    {
      case SYS_EXIT:
        sys_exit ((int) load_stack (frame, POS0));
        break;

      case SYS_WRITE:
        frame->eax = sys_write ((int) load_stack (frame, POS0),
            (const void *) load_stack (frame, POS1),
            (unsigned int) load_stack (frame, POS2));
        break;

      default:
        sys_exit (EXIT_ERROR_CODE); 
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

// check if valid buffer
bool valid_buffer(void *buffer, size_t length) {
  char *buffer_char = (char *)buffer;
  for (size_t i = 0; i < length; i++)
    if (!valid_usr_ptr(buffer_char + i)) return false;
  return true;
}

// terminate process with exitcode
void sys_exit (int status) {
  struct thread *ct = thread_current ();
  ct->exitcode = status;
  thread_exit ();
}


// buffered file write
int sys_write (int fd, const void *buffer, unsigned int length) {
  struct file_map *fileMap;
  unsigned int len;
  char *buffer_char;

  if (!valid_buffer ((void *) buffer, length)) sys_exit (EXIT_ERROR_CODE);

  if (fd == STDOUT_FILENO){ 
    len = length;
    buffer_char = (char *) buffer;

    while (len > MAXIMUM_BUFFER){
      putbuf ((const char *) buffer_char, MAXIMUM_BUFFER);
      len -= MAXIMUM_BUFFER;
      buffer_char += MAXIMUM_BUFFER;
    }
    putbuf ((const char *) buffer_char, len);
    return length;
  }
  fileMap = get_file_map (fd);
  if (fileMap == NULL) sys_exit (EXIT_ERROR_CODE);
  sema_down (&sema);
  int return_val = file_write (fileMap->file, buffer, length);
  sema_up (&sema);

  return return_val;
}


