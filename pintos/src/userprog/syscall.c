#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/off_t.h"
#include "threads/synch.h"
#include "vm/page.h"
#include <list.h>

struct file {
	struct inode* inode;
	off_t pos;
	bool deny_write;
};
struct lock file_lock;
static void syscall_handler (struct intr_frame *);
struct vm_entry* chkaddvld(void*);
void chkbufvld(void*, unsigned, void*, bool);
void chkstrvld(const void*, void*);

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
  chkaddvld(f->esp);
  switch(*(uint32_t*)sp) {
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		chkaddvld(f->esp+4);
		exit(*(uint32_t*)(f->esp+4));
		break;
	case SYS_EXEC:
		//chkaddvld(f->esp+4);
		chkstrvld((const void*)(f->esp+4), f->esp);
		f->eax = exec((const char*)*(uint32_t*)(f->esp+4));
		break;
	case SYS_WAIT:
		chkaddvld(f->esp+4);
		f->eax = wait((pid_t)*(uint32_t*)(f->esp+4));
		break;
	case SYS_CREATE:
		//chkaddvld(f->esp+4);
		//chkaddvld(f->esp+8);
		chkstrvld((const void*)(f->esp+4), f->esp);
		f->eax = create((const char*)*(uint32_t*)(f->esp+4), (unsigned)*(uint32_t*)(f->esp+8));
		break;
	case SYS_REMOVE:
		//chkaddvld(f->esp+4);
		chkstrvld((const void*)(f->esp+4), f->esp);
		f->eax = remove((const char*)*(uint32_t*)(f->esp+4));
		break;
	case SYS_OPEN:
		//chkaddvld(f->esp+4);
		chkstrvld((const void*)(f->esp+4), f->esp);
		f->eax = open((const char*)*(uint32_t*)(f->esp+4));
		break;
	case SYS_FILESIZE:
		chkaddvld(f->esp+4);
		f->eax = filesize((int)*(uint32_t*)(f->esp+4));
		break;
	case SYS_READ:
		//chkaddvld(f->esp+4);
		//chkaddvld(f->esp+8);
		//chkaddvld(f->esp+12);
		chkbufvld((void*)*(uint32_t*)(f->esp+8), (unsigned)*(uint32_t*)(f->esp+12), f->esp, 1);
		f->eax = read((int)*(uint32_t*)(f->esp+4), (void*)*(uint32_t*)(f->esp+8), (unsigned)*((uint32_t*)(f->esp+12)));
		break;
	case SYS_WRITE:
		//chkaddvld(f->esp+4);
		//chkaddvld(f->esp+8);
		//chkaddvld(f->esp+12);
		chkbufvld((void*)*(uint32_t*)(f->esp+8), (unsigned)*(uint32_t*)(f->esp+12), f->esp, 0);
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
	case SYS_MMAP:
		chkaddvld(f->esp+4);
		chkaddvld(f->esp+8);
		f->eax = mmap((int)*(uint32_t*)(f->esp+4), (void*)*(uint32_t*)(f->esp+8));
		break;
	case SYS_MUNMAP:
		chkaddvld(f->esp);
		munmap((int)*(uint32_t*)(f->esp+4));
		break;
	default:
		thread_exit ();
  }
}

struct vm_entry* chkaddvld(void* addr) {
	if(!is_user_vaddr(addr) || addr< (void*)0x08048000 || addr>= (void*)0xc0000000)
		exit(-1);
	struct vm_entry* vme = find_vme(addr);
	if(vme != NULL)
		return vme;
	exit(-1);
}

void chkbufvld(void* buffer, unsigned size, void* esp, bool to_write) {
	struct vm_entry* vme;
	void* buf = pg_round_down(buffer);
	int i;
	for(i = (int)size; i>0; i-= PGSIZE) {
		vme = chkaddvld(buf);
		if(vme == NULL || (to_write == true && vme->writable == false)) {
			exit(-1);
		}
		buf += PGSIZE;
	}
	for(i=0; i<size; i++) {
		vme = chkaddvld((void*)(buffer++));
		if(vme == NULL)
			exit(-1);
	}
}

void chkstrvld(const void* str, void* esp) {
	struct vm_entry* vme;
	void* _str = pg_round_down(str);
	vme = chkaddvld(_str);
	if(vme == NULL)
		exit(-1);
	int i;
	for(i = 0; ((char*)str)[i] != '\0'; i++) ;
	for(; i>0; i -= PGSIZE) {
		vme = chkaddvld(_str);
		if(vme == NULL)
			exit(-1);
		_str += PGSIZE;
	}
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
	lock_acquire(&file_lock);
	struct file* fp = thread_current()->fd[fd];
	thread_current()->fd[fd] = NULL;
	file_close(fp);
	lock_release(&file_lock);
}

mapid_t mmap(int fd, void* addr) {
	int mapid;
	struct vm_entry * found_vme;
	struct file* file;
	size_t offset = 0;

	if (fd < 2 || fd > 131 || (int)addr%PGSIZE != 0 || addr == 0)
		return -1;
	void* temp_addr = addr;
	int i;
	for(i=0; i<4;i++) {
		temp_addr = temp_addr + i;
		bool is_kernel = (int)is_kernel_vaddr(temp_addr);
		if(temp_addr == NULL || is_kernel || temp_addr < (void*)0x8048000)
			exit(-1);
	}
	if((found_vme = find_vme(addr)) != NULL || (file = process_get_file(fd)) == NULL){
		return -1;
	}
	file = file_reopen(file);
	int read_bytes = (int)file_length(file);
	if(read_bytes == 0){
		return -1;
	}
	struct mmap_file * mmfile = (struct mmap_file *)malloc(sizeof(struct mmap_file));
	if(mmfile == NULL){
		return -1;
	}
	mmfile->mapid = thread_current()->mapid++;
	mmfile->file = file;
	list_init(&mmfile->vme_list);
	list_push_back(&thread_current()->mmap_list, &mmfile->elem);
	while(read_bytes >0){
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		struct vm_entry * vme = (struct vm_entry*)malloc(sizeof(struct vm_entry));
		vme->type = VM_FILE;
		vme->vaddr = addr;
		vme->writable = true;
		vme->pinned = false;
		vme->is_loaded= false;
		vme->pinned = false;
		vme->file = file;
		vme->offset = offset;
		vme->read_bytes = page_read_bytes;
		vme->zero_bytes = page_zero_bytes;
		list_push_back(&mmfile->vme_list, &vme->mmap_elem);
		insert_vme(&thread_current()->vm, vme);
		offset += PGSIZE;
		read_bytes -= page_read_bytes;
		addr += PGSIZE;
	}
	return mmfile->mapid;
}

void munmap(mapid_t mapping) {
	struct list* mmap_list = &thread_current()->mmap_list;
	struct mmap_file* mmfile;
	struct list_elem* e;
	if(!list_empty(mmap_list)) {
		for(e = list_begin(mmap_list); e != list_end(mmap_list); e = list_next(e)) {
			mmfile = list_entry(e, struct mmap_file, elem);
			if(mmfile->mapid == mapping) {
				do_munmap(mmfile, e);
				break;
			}
		}
	}
}

