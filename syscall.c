#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/off_t.h"
#include "threads/synch.h"

struct file {
	struct inode* inode;
	off_t pos;
	bool deny_write;
};
struct lock file_lock;
static void syscall_handler (struct intr_frame *);
void chkaddvld(void*);
void getargs(void*, int*, int);

void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  void* sp = f->esp;
  switch(*(uint32_t*)sp) {
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		chkaddvld(f->esp+4);
		exit(*(uint32_t*)(f->esp+4));
		break;
	case SYS_EXEC:
		chkaddvld(f->esp+4);
		f->eax = exec((const char*)*(uint32_t*)(f->esp+4));
		break;
	case SYS_WAIT:
		chkaddvld(f->esp+4);
		f->eax = wait((pid_t)*(uint32_t*)(f->esp+4));
		break;
	case SYS_CREATE:
		chkaddvld(f->esp+4);
		chkaddvld(f->esp+8);
		f->eax = create((const char*)*(uint32_t*)(f->esp+4), (unsigned)*(uint32_t*)(f->esp+8));
		break;
	case SYS_REMOVE:
		chkaddvld(f->esp+4);
		f->eax = remove((const char*)*(uint32_t*)(f->esp+4));
		break;
	case SYS_OPEN:
		chkaddvld(f->esp+4);
		f->eax = open((const char*)*(uint32_t*)(f->esp+4));
		break;
	case SYS_FILESIZE:
		chkaddvld(f->esp+4);
		f->eax = filesize((int)*(uint32_t*)(f->esp+4));
		break;
	case SYS_READ:
		chkaddvld(f->esp+4);
		chkaddvld(f->esp+8);
		chkaddvld(f->esp+12);
		f->eax = read((int)*(uint32_t*)(f->esp+4), (void*)*(uint32_t*)(f->esp+8), (unsigned)*((uint32_t*)(f->esp+12)));
		break;
	case SYS_WRITE:
		chkaddvld(f->esp+4);
		chkaddvld(f->esp+8);
		chkaddvld(f->esp+12);
		f->eax = write((int)*(uint32_t *)(f->esp+4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
		break;
	case SYS_SEEK:
		chkaddvld(f->esp+4);
		chkaddvld(f->esp+8);
		seek((int)*(uint32_t*)(f->esp+4), (unsigned)*(uint32_t*)(f->esp+8));
		break;
	case SYS_TELL:
		chkaddvld(f->esp+4);
		f->eax = tell((int)*(uint32_t*)(f->esp+4));
		break;
	case SYS_CLOSE:
		chkaddvld(f->esp+4);
		close((int)*(uint32_t*)(f->esp+4));
		break;
	default:
		thread_exit ();
  }
}

void chkaddvld(void* add) {
	if(!is_user_vaddr(add))
		exit(-1);
}

void halt(void) {
	shutdown_power_off();
}

void exit(int status) {
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_current()->exit_status = status;
	int i;
	for(i=3; i<128; i++)
		if(thread_current()->fd[i] != NULL)
			close(i);
	thread_exit();
}

pid_t exec (const char *cmd_line) {
	return process_execute(cmd_line);
}

int wait (pid_t pid) {
	return process_wait(pid);
}

bool create(const char* file, unsigned initial_size) {
	if(file == NULL)
		exit(-1);
	chkaddvld(file);
	return filesys_create(file, initial_size);
}

bool remove(const char* file) {
	if(file == NULL)
		exit(-1);
	chkaddvld(file);
	return filesys_remove(file);
}

int open(const char* file) {
	if(file == NULL)
		exit(-1);
	chkaddvld(file);
	lock_acquire(&file_lock);
	struct file* fp = filesys_open(file);
	if(fp == NULL) {
		lock_release(&file_lock);
		return -1;
	}
	if(strcmp(thread_current()->name, file) == 0)
		file_deny_write(fp);
	int i;
	for (i = 3; i < 131; i++) {
		if (thread_current()->fd[i] == NULL) {
			thread_current()->fd[i] = fp;
			lock_release(&file_lock);
			return i;
		}
	}
	lock_release(&file_lock);
	return -1;
}

int filesize(int fd) {
	if(thread_current()->fd[fd] == NULL)
		exit(-1);
	return file_length(thread_current()->fd[fd]);
}

int read (int fd, void* buffer, unsigned size) {
	chkaddvld(buffer);
	lock_acquire(&file_lock);
	int i;
	if (fd == 0) {
		for (i = 0; i < size; i ++)
			if (((char *)buffer)[i] == '\0')
				break;
	}
	else if(fd>2) {
		if(thread_current()->fd[fd] == NULL)
			exit(-1);
		lock_release(&file_lock);
		return file_read(thread_current()->fd[fd], buffer, size);
	}
	lock_release(&file_lock);
	return i;
}

int write (int fd, const void *buffer, unsigned size) {
	chkaddvld(buffer);
	lock_acquire(&file_lock);
	if (fd == 1) {
		putbuf(buffer, size);
		lock_release(&file_lock);
		return size;
	}
	else if(fd>2) {
		if(thread_current()->fd[fd] == NULL) {
			lock_release(&file_lock);
			exit(-1);
		}
		if(thread_current()->fd[fd]->deny_write)
			file_deny_write(thread_current()->fd[fd]);
		lock_release(&file_lock);
		return file_write(thread_current()->fd[fd], buffer, size);
	}
	lock_release(&file_lock);
	return -1;
}

void seek(int fd, unsigned position) {
	if(thread_current()->fd[fd] == NULL)
		exit(-1);
	file_seek(thread_current()->fd[fd], position);
}

unsigned tell(int fd) {
	if(thread_current()->fd[fd] == NULL)
		exit(-1);
	return file_tell(thread_current()->fd[fd]);
}

void close(int fd) {
	if(thread_current()->fd[fd] == NULL)
		exit(-1);
	struct file* fp = thread_current()->fd[fd];
	thread_current()->fd[fd] = NULL;
	return file_close(fp);
}
