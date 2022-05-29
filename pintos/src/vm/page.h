#ifndef VM_PAGE_H
#define VM_PAGE_H

#define VM_BIN	0
#define VM_FILE	1
#define VM_ANON	2

#include <hash.h>

struct vm_entry {
	uint8_t type;
	void* vaddr;
	bool writable;
	bool is_loaded;
	struct file* file;
	struct list_elem mmap_elem;
	size_t offset;
	size_t read_bytes;
	size_t zero_bytes;
	size_t swap_slot;
	struct hash_elem elem;
	bool pinned;
};

void vm_init(struct hash* vm);
unsigned vm_hash_func(const struct hash_elem* e, void* aux);
bool vm_less_func(const struct hash_elem* a, const struct hash_elem* b, void* aux);
void vm_destroy(struct hash* vm);
void vm_destroyer(struct hash_elem* e, void* aux);

struct mmap_file {
	int mapid;
	struct file* file;
	struct list_elem elem;
	struct list vme_list;
};

void do_munmap(struct mmap_file*, struct list_elem*);

struct page {
	void* kaddr;
	struct vm_entry* vme;
	struct thread* thread;
	struct list_elem lru;
};
#endif
