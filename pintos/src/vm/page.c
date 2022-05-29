#include "vm/page.h"
#include <hash.h>
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"

void vm_init(struct hash* vm) {
	hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

unsigned vm_hash_func(const struct hash_elem* e, void* aux) {
	struct vm_entry* ve = hash_entry(e, struct vm_entry, elem);
	return hash_int((int)ve->vaddr);
}

bool vm_less_func(const struct hash_elem* a, const struct hash_elem* b, void* aux) {
	struct vm_entry* vea = hash_entry(a, struct vm_entry, elem);
	struct vm_entry* veb = hash_entry(b, struct vm_entry, elem);
	return vea->vaddr < veb->vaddr;
}

void vm_destroy(struct hash* vm) {
	hash_destroy(vm, vm_destroyer);
	file_close(thread_current()->binary_file);
}

void vm_destroyer(struct hash_elem* e, void* aux) {
	struct vm_entry* vme = hash_entry(e, struct vm_entry, elem);
	free(vme);
}

bool insert_vme(struct hash* vm, struct vm_entry* vme);
bool delete_vme(struct hash* vm, struct vm_entry* vme);
struct vm_entry* find_vme(void* vaddr);

bool insert_vme(struct hash* vm, struct vm_entry* vme) {
	return hash_insert(vm, &vme->elem) == NULL;
}

bool delete_vme(struct hash* vm, struct vm_entry* vme) {
	if(hash_delete(vm, &vme->elem) == NULL) {
		free(vme);
		return false;
	}
	free(vme);
	return true;
}

struct vm_entry* find_vme(void* vaddr) {
	struct vm_entry vme;
	vme.vaddr = pg_round_down(vaddr);
	struct thread* t = thread_current();
	struct hash_elem* e = hash_find(&t->vm, &vme.elem);
	if(!e)
		return NULL;
	return hash_entry(e, struct vm_entry, elem);
}

bool load_file(void* kaddr, struct vm_entry* vme);

bool load_file(void* kaddr, struct vm_entry* vme) {
	if(file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset) == (int)vme->read_bytes) {
		memset(kaddr+vme->read_bytes, 0, vme->zero_bytes);
		return true;
	}
	else
		return false;
}

void do_munmap(struct mmap_file* mmfile, struct list_elem* e) {
	struct vm_entry* vme;
	while(!list_empty(&mmfile->vme_list)) {
		vme = list_entry(list_pop_front(&mmfile->vme_list), struct vm_entry, mmap_elem);
		if((vme->is_loaded && pagedir_is_dirty(thread_current()->pagedir, vme->vaddr)) && (vme->read_bytes!=(size_t)file_write_at(vme->file, vme->vaddr, vme->read_bytes, vme->offset)))
			exit(-1);
		vme->is_loaded = false;
		delete_vme(&thread_current()->vm, vme);
	}
	list_remove(e);
	file_close(mmfile->file);
	free(mmfile);
}
