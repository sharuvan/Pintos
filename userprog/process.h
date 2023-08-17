#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

typedef int pid_t;

// File states
enum load_status
{
    NOT_LOADED,   /* Initial state */
    LOAD_SUCCESS, /* Loaded successfuly */
    LOAD_FAILED   /* Did not load */
};

/* Child process info struct */
struct process
{
    struct list_elem elem;        /* Child process list */
    pid_t pid;                    /* Process thread identity */
    bool alive;                   /* Process live status */
    bool waited;                  /* Process wait status */
    int exitcode;                 /* Process exit code */
    enum load_status load_status; /* Load status of file being executed */
    struct semaphore wait;        /* Wait for process to exit, then return state */
    struct semaphore load;        /* Wait for file to load or fail */
};

tid_t process_execute(const char *);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

bool esp_move(void **, size_t);
bool add_argv(void **, void **, int *);
bool add_args(void **, const char *);
bool add_values(void **, const char *);
void set_arg(const char *, char *);
void update_parent(struct thread *child);
void release_child(struct thread *t);
void update_parent_status(struct thread *child, enum load_status status);
struct process *initialize_process(tid_t);
struct process *get_child(struct thread *, tid_t);

#endif /* userprog/process.h */
