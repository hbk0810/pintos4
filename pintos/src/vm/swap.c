#include "vm/swap.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

const int BLOCK_PER_PAGE = PGSIZE/BLOCK_SECTOR_SIZE;

void swap_init(void) {
	swap_block = block_get_role(BLOCK_SWAP);
	if(swap_block == NULL)
		return;
	swap_bitmap = bitmap_create(block_size(swap_block)/BLOCK_PER_PAGE);
	lock_init(&swap_lock);
}

void swap_in(size_t used_index, void* kaddr) {
	swap_block = block_get_role(BLOCK_SWAP);
	int i;
	if(!bitmap_test(swap_bitmap, used_index))
		exit(-1);
	lock_acquire(&swap_lock);
	for (i = 0; i < BLOCK_PER_PAGE; i++) {
		block_read(swap_block, BLOCK_PER_PAGE*used_index+i, BLOCK_SECTOR_SIZE*i+kaddr);
	}
	bitmap_reset(swap_bitmap, used_index);
	lock_release(&swap_lock);
}

size_t swap_out(void* kaddr) {
	swap_block = block_get_role(BLOCK_SWAP);
	size_t swap_index = bitmap_scan(swap_bitmap, 0, 1, false);
	int i;
	lock_acquire(&swap_lock);
	if(swap_index != BITMAP_ERROR) {
		for(i=0; i<BLOCK_PER_PAGE; i++) {
			block_write(swap_block, swap_index*BLOCK_PER_PAGE+i, i*BLOCK_SECTOR_SIZE+kaddr);
		}
		bitmap_set(swap_bitmap, swap_index, true);
	}
	lock_release(&swap_lock);
	return swap_index;
}

