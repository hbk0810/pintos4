#include "vm/frame.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

void lru_list_init(void) {
	list_init(&lru_list);
	lock_init(&lru_list_lock);
	lru_clock = NULL;
}

void add_page_to_lru_list(struct page* page) {
	list_push_back(&lru_list, &page->lru);
}

void del_page_from_lru_list(struct page* page) {
	if(lru_clock == &page->lru)
		lru_clock = list_next(lru_clock);
	list_remove(&page->lru);
}

struct page* alloc_page(enum palloc_flags flags) {
	struct page* page;
	void* kaddr = palloc_get_page(flags);
	lock_acquire(&lru_list_lock);
	while(kaddr == NULL) {
		try_to_free_pages(flags);
		kaddr = palloc_get_page(flags);
	}
	page = (struct page*)malloc(sizeof(struct page));
	page->kaddr = kaddr;
	page->thread = thread_current();
	add_page_to_lru_list(page);
	lock_release(&lru_list_lock);
	return page;
}

void free_page(void* kaddr) {
	struct page* page;
	struct list_elem* e;
	lock_acquire(&lru_list_lock);
	for(e=list_begin(&lru_list); e!=list_end(&lru_list); e=list_next(e)) {
		page = list_entry(e, struct page, lru);
		if(page->kaddr == kaddr) {
			__free_page(page);
			break;
		}
	}
	lock_release(&lru_list_lock);
}

void __free_page(struct page* page) {
	del_page_from_lru_list(page);
	palloc_free_page(page->kaddr);
	free(page);
}

struct list_elem* get_next_lru_clock() {
	if(list_empty(&lru_list))
		return NULL;
	else if(lru_clock == NULL)
		return list_begin(&lru_list);
	else if(list_next(lru_clock) == list_end(&lru_list))
		return list_begin(&lru_list);
	else
		return list_next(lru_clock);
}

void try_to_free_pages(enum palloc_flags flags) {
	struct page* page;
	lru_clock = get_next_lru_clock();
	page = list_entry(lru_clock, struct page, lru);
	while(pagedir_is_accessed(page->thread->pagedir, page->vme->vaddr)||page->vme->pinned) {
		pagedir_set_accessed(page->thread->pagedir, page->vme->vaddr, false);
		lru_clock = get_next_lru_clock();
		page = list_entry(lru_clock, struct page, lru);
	}
	bool dirty_bit = pagedir_is_dirty(page->thread->pagedir, page->vme->vaddr);
	switch(page->vme->type) {
		case VM_BIN:
			if(dirty_bit) {
				page->vme->swap_slot = swap_out(page->kaddr);
				page->vme->type = VM_ANON;
			}
			break;
		case VM_FILE:
			if(dirty_bit) {
				file_write_at(page->vme->file, page->vme->vaddr, page->vme->read_bytes, page->vme->offset);
			}
			break;
		case VM_ANON:
			page->vme->swap_slot = swap_out(page->kaddr);
			break;
	}
	page->vme->is_loaded = false;
	pagedir_clear_page(page->thread->pagedir, pg_round_down(page->vme->vaddr));
	__free_page(page);
}

