/* KTLS - Kernel Thread-Level Speculation
 * KTLS is a part of the sambamba framework
 *
 * ktls.c - Implementation of the kernel module
 * Authors: Janosch Graef <janosch.graef@gmx.net>
 *          Clemens Hammacher <hammacher@cs.uni-saarland.de>
 *          Daniel Birtel <daniel.birtel@stud.uni-saarland.de>
 *
 *
 * First Approach:
 * - install new VMA with own vm_operations_struct
 * - on read fault, map the parent page to the child, and store this
 * - on write fault, copy the parent page, and add the copy to the child (+ store this)
 * - on page_mkwrite, record that the page was modified
 *
 * Problem:
 * - in handle_pte_fault, the kernel makes copy-on-write (COW) of anonymous pages without a way to interfere or observe this (it calls do_wp_page)
 *
 *
 * ==> Second approach: Always only provide the kernel with the parent page, let him do the COW, and check after termination which pages have been copied.
 * - on each fault (no matter if read or write), store:
 *   - address
 *   - pfn which has been copied
 * - before commit, compare that all store PFNs are still in the parent PTE, otherwise conflict.
 * - on commit, compare the stored PFN with child PTE. if equals -> read only, otherwise -> write.
 */

// Unfortunately, we cannot keep this list sorted, since there are some dependencies
// in the includes (e.g. pgtable.h uses spinlock_t without including a corresponding
// header before).
#include <linux/cdev.h> /* character device stuff (for /dev/ktls) */
#include <linux/completion.h> /* completion */
#include <linux/delay.h> /* msleep */
#include <linux/device.h>
#include <linux/fs.h> /* FS operations, ... */
#include <linux/kallsyms.h> /* kallsyms_lookup_name */
#include <linux/kernel.h>
#include <linux/kthread.h> /* kthread_create, kthread_stop, ... */
#include <linux/module.h>
#include <linux/mm.h> /* VM_READ, ... */
#include <linux/mm_types.h> /* struct vm_area_struct, struct mm_struct, ... */
#include <linux/pagemap.h> /* lock_page */
#include <linux/sched.h>     /* struct task_struct, schedule, ... */
#include <linux/semaphore.h> /* semaphore */
#include <linux/slab.h> /* kmalloc, kfree */
#include <linux/sort.h> /* sort */
#include <linux/spinlock.h> /* spinlock_t */
#include <linux/rwlock_types.h> /* rw_lock_t */
#include <linux/string.h> /* memcpy, memset, ... */
#include <linux/task_work.h> /* task_work_add */
#include <linux/types.h> /* uint16_t, uint32_t, ... */
#include <linux/uaccess.h> /* copy_to_user, copy_from_user, ... */
#include <linux/wait.h> /* wait flags */

#include <asm/current.h> /* current */
#include <asm/page.h> /* pte_t, ... */
#include <asm/pgtable.h> /* mk_pte */

#include <uapi/linux/stat.h> /* S_IRUSR etc. */

#include "TLS/ktls_ioctl.h"

#include "ktls_assert.h"
#include "ktls_hhash.h"
#include "ktls_hhash_adapter.h"
#include "ktls_vector.h"
#include "syscalls.h"

MODULE_LICENSE("GPL");

static int debug = 2;
module_param(debug, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(debug, "amount of debug output (smaller is always included) "
        "(0: ERR, 1: WARN, 2: NOTICE (default), 3: INFO, 4: DEBUG); "
        "3 and greater only available in debug build");
static int accu = 1;
module_param(accu, int, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(accu, "boolean variable which determines whether conflict "
                       "checking uses an accumulator for previous task's "
                       "changes, or checks against individual tasks directly");

#define KMSG(DBGLEVEL, MSGLEVEL, ...)                                          \
  do {                                                                         \
    if (debug >= DBGLEVEL)                                                     \
      printk(MSGLEVEL "KTLS[" #DBGLEVEL "]: " __VA_ARGS__);                    \
  } while (0)
#define KERR(...)    KMSG(0, KERN_ERR,  __VA_ARGS__)
#define KWARN(...)   KMSG(1, KERN_WARNING,  __VA_ARGS__)
#define KNOTICE(...) KMSG(2, KERN_NOTICE,  __VA_ARGS__)

#ifndef NDEBUG
# define KINFO(...)  KMSG(3, KERN_INFO,  __VA_ARGS__)
# define KDEBUG(...) KMSG(4, KERN_DEBUG,  __VA_ARGS__)
#else
# define KINFO(...)  do {} while (0)
# define KDEBUG(...) do {} while (0)
#endif

typedef void (*sys_call_ptr_t)(void);

#define DEF_KERNEL_SYM(name, type) static type *kernel_##name;
#define DEF_KERNEL_FUNC(name, rettype, ...)                                    \
  static rettype (*kernel_##name)(__VA_ARGS__);
#define INIT_KERNEL_FUNC_OR_SYM(name, rettype, ...)                            \
  kernel_##name = ktls_find_kernel_symbol(#name, &ret);
#define KERNEL_SYMBOLS(FUNC, SYM)                                              \
  FUNC(change_protection, unsigned long, struct vm_area_struct *vma,           \
       unsigned long start, unsigned long end, pgprot_t newprot,               \
       int dirty_accountable, int prot_numa)                                   \
      FUNC(find_task_by_vpid, struct task_struct *, pid_t nr)                  \
      FUNC(mmput, void *, struct mm_struct *mm)                                \
      FUNC(vma_adjust, int, struct vm_area_struct *vma, unsigned long start,   \
           unsigned long end, pgoff_t pgoff, struct vm_area_struct *insert)    \
      FUNC(__get_locked_pte, pte_t *, struct mm_struct *mm,                    \
           unsigned long address, spinlock_t **ptl)                            \
      FUNC(page_add_anon_rmap, void, struct page *page,                        \
           struct vm_area_struct *vma, unsigned long address)                  \
      FUNC(page_add_new_anon_rmap, void, struct page *page,                    \
           struct vm_area_struct *vma, unsigned long address)                  \
      FUNC(page_add_file_rmap, void, struct page *page)                        \
      FUNC(page_remove_rmap, void, struct page *page)                          \
      FUNC(insert_vm_struct, int, struct mm_struct *mm,                        \
           struct vm_area_struct *vma)                                         \
      FUNC(anon_vma_fork, int, struct vm_area_struct *vma,                     \
           struct vm_area_struct *pvma)                                        \
      FUNC(anon_vma_prepare, int, struct vm_area_struct *vma)                  \
      FUNC(find_task_by_vpid, struct task_struct *, pid_t vnr)                 \
      FUNC(do_fork, long, unsigned long, unsigned long, unsigned long, int *,  \
           int *) FUNC(vma_rb_erase, void, struct vm_area_struct *vma,         \
                       struct rb_root *root)                                   \
      FUNC(do_munmap, int, struct mm_struct *, unsigned long, size_t)          \
      FUNC(wait_task_inactive, unsigned long, struct task_struct *, long)      \
      FUNC(follow_page_mask, struct page *, struct vm_area_struct *,           \
           unsigned long, unsigned int, unsigned int *)                        \
      FUNC(handle_mm_fault, int, struct mm_struct *, struct vm_area_struct *,  \
           unsigned long, unsigned int)                                        \
      FUNC(flush_tlb_current_task, void, void)                                 \
      FUNC(vm_normal_page, struct page *, struct vm_area_struct *vma,          \
           unsigned long addr, pte_t pte)                                      \
      FUNC(task_work_add, int, struct task_struct *task,                       \
           struct callback_head *twork, bool)                                  \
      SYM(vm_area_cachep, struct kmem_cache *)                                 \
      SYM(sys_call_table, sys_call_ptr_t)                                      \
      FUNC(zap_page_range, void, struct vm_area_struct *vma,                   \
           unsigned long start, unsigned long size,                            \
           struct zap_details *details)                                        \
      FUNC(set_memory_rw, int, unsigned long addr, int numpages)               \
      FUNC(exit_files, void, struct task_struct *tsk)

#define PAGE_ROUNDDOWN(a) ((a) & PAGE_MASK)
#define PAGE_ROUNDUP(a) (PAGE_ROUNDDOWN(a) + PAGE_SIZE)

#define CHILD_STACK_SIZE (16*1024*1024) /* 16 MB */

/* Magic used to check contexts and VMA data */
#if defined __x86__
#define KTLS_MAGIC 0x4b544c53
#elif defined __x86_64__
#define KTLS_MAGIC 0x4b544c534b544c53
#endif

#define FORCE_USE __attribute__((warn_unused_result))

#define SHAD_READ_MASK 0b01010101
#define SHAD_WRITE_MASK 0b10101010

/* A TLS task as passed from user space.
 * This MUST match the layout of TLS::TLSTask.
 */
struct tls_task {
    union {
        struct {
            uint16_t input_size;
            uint16_t output_size;
        };
        uint32_t sizes;
    };
    void (*function)(void*,void*);
};

/*
 * This structure represents a page / PTE which has been copied from the parent to the child.
 * During commit, it's information is used to determine whether both child and parent PTE still
 * point to the same page, which means the pages has been read only, or whether a COW happened
 * after the mapping.
 *
 * TODO: we could also store the version number at the time when we first mapped this page.
 * This might reduce the number of conflict.
 */
struct ktls_touched_page {
    // address of the page (4k-aligned)
    // TODO check if the address is really needed (maybe only in debug build)
    unsigned long address;

    // PFN when this page was transferred from parent to child
    unsigned long orig_pfn;
};

int touched_pages_cmp(const void *p1, const void *p2) {
  unsigned long addr1 = ((struct ktls_touched_page*)p1)->address;
  unsigned long addr2 = ((struct ktls_touched_page*)p2)->address;
  ASSERT(addr1 != addr2);
  return addr1 < addr2 ? -1 : 1;
}
void touched_pages_swap(void *v1, void *v2, int size) {
  struct ktls_touched_page *p1 = (struct ktls_touched_page*)v1;
  struct ktls_touched_page *p2 = (struct ktls_touched_page*)v2;
  ASSERT(size == sizeof(*p1));
  struct ktls_touched_page tmp = *p1;
  *p1 = *p2;
  *p2 = tmp;
}

struct ktls_task {
    struct ktls_ctx *ctx;

    // Pointer to the function to execute.
    unsigned long func;

    // Sizes of input and output.
    unsigned short input_size;
    unsigned short output_size;

    // address of the output struct in the parent
    unsigned long output_addr;

    // This kernel memory holds the task input and output.
    // Input is filled on task creation, and is copied to the first stack page
    // in ktls_handle_stack_page. The task loads values from there.
    // Output is filled from the stack page (where the task wrote outputs) to
    // this memory when the task terminates (also in ktls_handle_stack_fault).
    // From there, it is copied to the right location in the parent process
    // (at address <output_addr>) in ktls_commit.
    union {
        char input_output[64];
        char *more_input_output;
    };

    // The sequence number of this task
    unsigned seq_nr;

    // Pointer to the kernel task which executes this TLS task.
    // This is NULL until the first stack fault happens.
    struct task_struct *task;

    // Pointer to the mm_struct of the executing task. In the task_struct,
    // this is set to NULL on termination of the task, so we save it here.
    struct mm_struct *mm;

    /*
     * The version number (= sequence number of last committed task)
     * when this task was spawned.
     */
    unsigned version_on_start;

#define KTLS_TASK_FINISHED 0
#define KTLS_TASK_SUCCESS 1
#define KTLS_TASK_IRREVOCABLE 2
#define KTLS_TASK_REUSED 3
    /**
     * Flags:
     * - finished:
     *   Set by the stack fault handler, when the child returns from the
     *   user function.
     * - success:
     *   Set to false when spawned, and to true if the user function returns.
     *   If for example a system call happens during execution, or the process
     *   is killed some other way, it remains false and indicates failure.
     * - irrevocable:
     *   Set on the first syscall, after waiting to be "master" task (i.e.
     *   next one to commit) and checking that no conflicts occured so far.
     * - reused:
     *   Flag to indicate whether this task uses a "reused" process.
     *   In this case, some setup can be skipped.
     */
    volatile long state;

    /* Vector of read and written pages. Two entries constitude one element
     * (first entry is virtual address, second entry PFN at time of copy). */
    struct ktls_vector touched_pages;

    /**
     * Timestamp of the first page fault of this task (i.e. start of executing
     * the user code.
     */
    ktime_t time_start;
};

struct ktls_protected_vma_info {
    unsigned long vm_start;
    unsigned long vm_end;
    unsigned long vm_flags;
};
struct ktls_protected_memory_info {
    unsigned num_areas;
    union {
        struct ktls_protected_vma_info areas[16]; // first 16 areas stored directly in the struct
        struct {
            struct ktls_protected_vma_info *arr;
            unsigned capacity;
        } more_areas; // if more than 16 elements.
    };
};

/* A ktls context.
 * When a process opens a file a context is opened and attached to
 * the file handle and all protected VMAs. This is used for bookkeeping.
 */
struct ktls_ctx {
#ifndef NDEBUG
    /* magic to check if pointer really points to a ktls context */
    long magic;
#endif

    /* The parent process of this context */
    struct task_struct *parent;

    /* Make sure to hold the ktls_open_contexts_lock before modifying num_tasks or tasks */
    /* Number of tasks in current transaction or 0 if no transaction running */
    unsigned num_tasks;
    /* Array of tasks or NULL of no transaction running */
    struct ktls_task *tasks;

    /* a flag to indicate that the context is shutting down */
    unsigned shutting_down : 1;

    unsigned long trampoline_task_function;

    /* set of PFNs which have been modified, plus their version (= seq nr of last modification) */
    struct ktls_hhash pfn_versions;

    /*
     * The (virtual == user-space) address of the stack.
     * A corresponding vma is added to the parent mm, and cloned to all children.
     * This address is the base. The stack is CHILD_STACK_SIZE bytes large. The
     * top page is not used, but rather it's address is written to the initial
     * stack as return address
     */
    unsigned long stack_vm_addr;

    /*
     * The vma for the child stacks.
     * Its vm_private_data is a pointer to the ktls_task, so that the child
     * can set up everything else in its mm on the first stack page fault.
     */
    struct vm_area_struct *parent_stack_vma;

    /*
     * These fields are only accessed from the parent, so no synchronization needed.
     */
    unsigned last_committed_version;
    unsigned last_started_version;

    /**
     * statistics for this context. Can be retrieved from user space via
     * KTLS_IOCTL_STATS ioctl.
     */
    struct ktls_stats stats;

    /**
     * a stack of tasks which can re reused to execute other tasks.
     */
    spinlock_t reuse_stack_lock;

    struct task_struct **reuse_stack;
    unsigned reuse_stack_size;
    unsigned reuse_stack_cap;

    /**
     * reference counter: when it drops to zero, this context is freed.
     */
    atomic_t ref_count;
};


/* basic operations on the context */
static FORCE_USE int ktls_add_open_context(struct ktls_ctx *ctx);
static FORCE_USE struct ktls_ctx *ktls_new_ctx(void);
static void ktls_shutdown_ctx(struct ktls_ctx *ctx);
static void ktls_free_ctx(struct ktls_ctx *ctx);
static void ktls_get_ctx(struct ktls_ctx *ctx);
static void ktls_put_ctx(struct ktls_ctx *ctx);

/* task operations */
static struct ktls_task *ktls_find_task(struct task_struct *t);

/* KTLS device */
static int ktls_dev_open(struct inode *inode, struct file *file);
static int ktls_dev_release(struct inode *inode, struct file *file);
static ssize_t ktls_dev_read(struct file *filp, char __user *buf, size_t len, loff_t __user *off);
static ssize_t ktls_dev_write(struct file *filp, const char __user *buf, size_t len, loff_t __user *off);
static long ktls_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);


/* some function pointers we collect from kernel */
KERNEL_SYMBOLS(DEF_KERNEL_FUNC, DEF_KERNEL_SYM)


/* Fault handler: */
static int ktls_handle_fault(struct vm_area_struct *vma, struct vm_fault *vmf);
static int ktls_handle_stack_fault(struct vm_area_struct *vma, struct vm_fault *vmf);

static const struct vm_operations_struct ktls_vm_operations = {
        .fault = ktls_handle_fault,
};

static const struct vm_operations_struct ktls_vm_stack_operations = {
        .fault = ktls_handle_stack_fault,
};


/* some other device stuff */
static struct class *ktls_dev_class;
static struct device *ktls_dev_device;
static dev_t ktls_dev_chrdev;
static struct cdev ktls_dev_cdev;

/* File operations on the ktls device */
static struct file_operations ktls_dev_fops = {
  .read = ktls_dev_read,
  .write = ktls_dev_write,
  .open = ktls_dev_open,
  .release = ktls_dev_release,
  .unlocked_ioctl = ktls_dev_ioctl
};


/*
 * Keep track of all currently open contexts, in order to
 * determine if a specific task is running inside KTLS, e.g.
 * when encountering a system call.
 */
#define KTLS_MAX_CONTEXTS 2
static struct ktls_ctx *ktls_open_contexts[KTLS_MAX_CONTEXTS];
static unsigned ktls_num_open_contexts = 0;
static rwlock_t ktls_open_contexts_lock;

/*
 * Flag to indicate that ktls is currently shutting down.
 * If this is set, no new contexts can be opened.
 */
static unsigned ktls_shutting_down = 0;

/*
 * A kernel thread which periodically checks for open contexts whose parent is
 * dead, and removes them.
 */
struct task_struct *ktls_ctx_cleanup_thread = NULL;

/**
 * Get or create a PTE. If create==0, then no PTE will be created.
 * Returns NULL if the PTE was not present or could not be created.
 * On success, the PTE is mapped and locked, so the caller is
 * responsible for unmapping and unlocking both (use pte_unmap_unlock).
 *
 * If you want to create a non-existing PTE, use kernel___get_locked_pte.
 *
 * This function must be called with mmap_sem hold at least for reading.
 */
static pte_t *get_pte_if_present(struct mm_struct *mm, unsigned long address,
        spinlock_t **ptlp)
{
    ASSERT(mm);
    ASSERT(mm->pgd);
    ASSERT(ptlp);

    pgd_t *pgd = pgd_offset(mm, address);
    if (unlikely(pgd_none(*pgd)) || unlikely(pgd_bad(*pgd)))
        return NULL;
    pud_t *pud = pud_offset(pgd, address);
    if (unlikely(pud_none(*pud)) || unlikely(pud_bad(*pud)))
        return NULL;
    pmd_t *pmd = pmd_offset(pud, address);
    if (unlikely(pmd_none(*pmd)) || unlikely(pmd_bad(*pmd)))
        return NULL;
    pte_t *pte = pte_offset_map_lock(mm, pmd, address, ptlp);

    return pte;
}


/* copied (and modified) from pagemap.h:linear_page_index */
static inline pgoff_t ktls_page_index(struct vm_area_struct *vma,
        unsigned long address)
{
    ASSERT (!is_vm_hugetlb_page(vma));
    pgoff_t pgoff = (address - vma->vm_start) >> PAGE_SHIFT;
    pgoff += vma->vm_pgoff;
    return pgoff >> (PAGE_CACHE_SHIFT - PAGE_SHIFT);
}

/*
static const char *flags_to_str(long flags) {
    _Static_assert((VM_READ | VM_WRITE | VM_EXEC | VM_SHARED) == 15, "unexpected VM_* constants");
    const char *flag_strs = "----\0r---\0-w--\0rw--\0--x-\0r-x-\0-wx-\0rwx-\0"
                            "---s\0r--s\0-w-s\0rw-s\0--xs\0r-xs\0-wxs\0rwxs\0";
    return flag_strs + 5 * (flags & (VM_READ | VM_WRITE | VM_EXEC | VM_SHARED));
}

static void ktls_print_vma(struct vm_area_struct *vma) {
    KNOTICE("VMA@%p: [0x%lx - 0x%lx]: flags=p:%s/r:%s, priv=%p, file=%p, f=%6lx, ops=%p\n",
            vma, vma->vm_start, vma->vm_end, flags_to_str(vma->vm_flags),
            flags_to_str(vma->vm_flags >> 4), vma->vm_private_data,
            vma->vm_file, vma->vm_flags, vma->vm_ops);
}

static void ktls_print_mm(struct mm_struct *mm) {
    for (struct vm_area_struct *vma = mm->mmap; vma; vma = vma->vm_next) {
        ktls_print_vma(vma);
    }
}
*/


/**
 * Hold the mm->mmap_sem for writing when calling this function.
 */
static struct vm_area_struct *ktls_new_vma(struct mm_struct *mm, unsigned long vm_start,
        unsigned long vm_end, unsigned long vm_pgoff, unsigned long vm_flags,
        void *vm_file, void *vm_private_data, const struct vm_operations_struct *vm_ops,
        struct vm_area_struct *parent_vma) {
    ASSERT ((vm_start & PAGE_MASK) == vm_start);
    ASSERT ((vm_end & PAGE_MASK) == vm_end);

    struct vm_area_struct *vma = kmem_cache_zalloc(*kernel_vm_area_cachep, GFP_KERNEL);
    int err = -ENOMEM;
    if (!vma)
        goto out;

    INIT_LIST_HEAD(&vma->anon_vma_chain);
    vma->vm_mm = mm;
    vma->vm_start = vm_start;
    vma->vm_end = vm_end;
    vma->vm_flags = vm_flags;
    vma->vm_page_prot = vm_get_page_prot(vm_flags);
    vma->vm_ops = vm_ops;
    vma->vm_file = vm_file;
    vma->vm_private_data = vm_private_data;
    err = kernel_insert_vm_struct(mm, vma);
    if (err)
        goto free_vma;

    if (vm_file)
        get_file(vm_file);

    mm->total_vm += (vm_end - vm_start) >> PAGE_SHIFT;

    // ARGH, this has to be set *after* insert_vm_struct, because this function overwrites it
    vma->vm_pgoff = vm_pgoff;

    if (parent_vma) {
        err = kernel_anon_vma_fork(vma, parent_vma);
        if (err)
            goto out;
    }

    return vma;

free_vma:
    kmem_cache_free(*kernel_vm_area_cachep, vma);
out:
    return ERR_PTR(err);
}

/*
static void ktls_remove_vma(struct mm_struct *mm, struct vm_area_struct *vma) {
    ASSERT (vma->vm_mm == mm);

    struct vm_area_struct *next = vma->vm_next;
    struct vm_area_struct *prev = vma->vm_prev;

    if (prev) {
        prev->vm_next = next;
        if (next)
            next->vm_prev = prev;
        if (mm->mmap_cache == vma)
            mm->mmap_cache = prev;
    } else {
        ASSERT (mm->mmap == vma);
        mm->mmap = next;
        if (mm->mmap_cache == vma)
            mm->mmap_cache = next;
    }

    kmem_cache_free(*kernel_vm_area_cachep, vma);

    // This does not work, since the rb_subtree_gap values
    // are invalid after the removal above, so a bug will be
    // detected.
    // Doing it before will compute invalid gap values, so the
    // bug will be triggered later.
    // Currently, I resort to calling do_munmap, which has a bit
    // of overhead, but not too much.
    kernel_vma_rb_erase(vma, &mm->mm_rb);
}
*/

static FORCE_USE int ktls_task_init(struct ktls_task *task,
                                    struct tls_task *tls_task,
                                    unsigned long output_addr,
                                    struct ktls_ctx *ctx) {
    task->ctx = ctx;

    task->state = 0;

    task->func = (unsigned long)tls_task->function;

    task->input_size = tls_task->input_size;
    task->output_size = tls_task->output_size;
    task->output_addr = output_addr;

    if (tls_task->input_size + tls_task->output_size > sizeof(task->input_output)) {
        task->more_input_output = kmalloc(tls_task->input_size + tls_task->output_size, GFP_KERNEL);
        if (!task->more_input_output) {
            KERR("cannot allocate the input/output struct of %d bytes\n",
                    tls_task->input_size + tls_task->output_size);
            return VM_FAULT_OOM;
        }
    }

    task->seq_nr = ++ctx->last_started_version;

    ktls_vector_init(&task->touched_pages);

    return 0;
}

static struct ktls_task *ktls_get_task(struct vm_area_struct *vma) {
    struct ktls_task *task = vma->vm_private_data;
    ASSERT(task && task->ctx);
    ASSERT(task >= task->ctx->tasks &&
           task < task->ctx->tasks + task->ctx->num_tasks);
    return task;
}

static struct ktls_ctx *ktls_ctx_from_file(struct file *f) {
    struct ktls_ctx *ctx = f->private_data;
    if (f->f_op != &ktls_dev_fops || ctx == NULL)
      return NULL;
    ASSERT(ctx->magic == KTLS_MAGIC);
    return ctx;
}

static int ktls_is_protected_vma(struct vm_area_struct *vma) {
    if ((vma->vm_flags & VM_WRITE) == 0)
        return 0;
    if (vma->vm_ops == &ktls_vm_stack_operations)
        return 0;
    return 1;
}

/*
 * this function locks the mmap_sem of ctx->parent->mm for writing.
 */
static FORCE_USE int ktls_prepare_parent_mm(struct ktls_ctx *ctx) {
    ASSERT (ctx->parent == current);
    struct mm_struct *mm = ctx->parent->mm;
    int ret = 0;

    KINFO("preparing parent mm (%p)\n", mm);
    down_write(&mm->mmap_sem);

    struct vm_area_struct *stack_vma = 0;
    for (struct vm_area_struct *vma = mm->mmap; vma; vma = vma->vm_next) {
      if (!ktls_is_protected_vma(vma)) {
        if (vma->vm_ops == &ktls_vm_stack_operations) {
          ASSERT(stack_vma == 0);
          stack_vma = vma;
        }
        continue;
      }
      ASSERT((vma->vm_flags & VM_DONTCOPY) == 0 &&
             "Unsupported: VM_DONTCOPY already set");
      vma->vm_flags |= VM_DONTCOPY;
      ret = kernel_anon_vma_prepare(vma);
      if (unlikely(ret))
        goto unlock;
    }

    /* find a place for 16 MB stack */
    unsigned long stack_vm_addr;
    if (stack_vma != 0) {
      stack_vm_addr = stack_vma->vm_start;
    } else {
      stack_vm_addr = mm->get_unmapped_area(NULL, 0, CHILD_STACK_SIZE, 0, 0);
      if (stack_vm_addr & ~PAGE_MASK) {
        ret = stack_vm_addr;
        goto unlock;
      }

      /* add new vma for the stack */
      stack_vma =
          ktls_new_vma(mm, stack_vm_addr, stack_vm_addr + CHILD_STACK_SIZE, 0,
                       VM_READ | VM_WRITE, 0, 0, &ktls_vm_stack_operations, 0);
      if (IS_ERR(stack_vma)) {
        ret = PTR_ERR(stack_vma);
        goto unlock;
      }
    }

    ASSERT(ctx->stack_vm_addr == 0);
    ctx->stack_vm_addr = stack_vm_addr;
    ctx->parent_stack_vma = stack_vma;

unlock:
    up_write(&mm->mmap_sem);

    return ret;
}

/*
 * this function locks the mmap_sem of ctx->parent->mm for writing.
 */
static FORCE_USE int ktls_reset_parent_mm(struct ktls_ctx *ctx) {
    struct mm_struct *mm = ctx->parent->mm;
    down_write(&mm->mmap_sem);
    for (struct vm_area_struct *vma = mm->mmap; vma; vma = vma->vm_next) {
        if (!ktls_is_protected_vma(vma))
            continue;
        // TODO somehow, new mappings are created during execution of the child
        // processes, without the VM_DONTCOPY set...
        // ASSERT ((vma->vm_flags & VM_DONTCOPY) != 0);
        vma->vm_flags &= ~VM_DONTCOPY;
    }
    int error = 0;
    /*
    int error = kernel_do_munmap(mm, ctx->stack_vm_addr, CHILD_STACK_SIZE);
    if (error)
        KNOTICE("Error unmapping the stack VMA (code %d)\n", error);
    //ktls_remove_vma(mm, ctx->parent_stack_vma);
    */

    ctx->stack_vm_addr = 0;

    up_write(&mm->mmap_sem);
    return error;
}


/**
 * This function assumes that the task->task->mm->mmap_sem is held for reading.
 */
static FORCE_USE int ktls_mm_setup(struct ktls_task *task) {
  ASSERT(!test_bit(KTLS_TASK_REUSED, &task->state));
  int ret = 0;
  struct mm_struct *mm = task->task->mm;
  struct mm_struct *parent_mm = task->ctx->parent->mm;

  KINFO("protecting mm %p of pid=%d, seq_nr=%d\n", mm, task->task->pid,
        task->seq_nr);
  // KDEBUG("mm before\n");
  // ktls_print_mm(mm);

  up_read(&mm->mmap_sem);
  down_write(&mm->mmap_sem);

  for (struct vm_area_struct *pvma = parent_mm->mmap; pvma;
       pvma = pvma->vm_next) {
    if ((pvma->vm_flags & VM_DONTCOPY) == 0)
      continue;
    struct vm_area_struct *vma =
        ktls_new_vma(mm, pvma->vm_start, pvma->vm_end, pvma->vm_pgoff,
                     VM_READ | VM_WRITE | VM_EXEC, pvma->vm_file, task,
                     &ktls_vm_operations, pvma);
    if (IS_ERR(vma)) {
      ret = PTR_ERR(vma);
      goto out;
    }
  }

// KDEBUG("mm after");
// ktls_print_mm(mm);

out:
  downgrade_write(&mm->mmap_sem);

  return ret;
}

static void ktls_free_task(struct ktls_task *t) {
  KDEBUG("pid %d freeing task %p (seq_nr=%d)\n", current->pid, t, t->seq_nr);
  ktls_vector_free(&t->touched_pages);
  if (t->input_size + t->output_size > sizeof(t->input_output))
    kfree(t->more_input_output);
}

/**
 * Return 1 if successful, 0 otherwise (ctx is already shutting down).
 */
static FORCE_USE int put_task_in_reuse_queue(struct task_struct *t,
                                             struct ktls_ctx *ctx) {
  ASSERT(t == current);

  // zap all PTEs:
  KINFO("zapping all PTEs of task (pid=%d) -> anon %ld, file %ld\n", t->pid,
        get_mm_counter(t->mm, MM_ANONPAGES),
        get_mm_counter(t->mm, MM_FILEPAGES));
  for (struct vm_area_struct *vma = t->mm->mmap; vma; vma = vma->vm_next)
    if (vma->vm_ops == &ktls_vm_operations)
      kernel_zap_page_range(vma, vma->vm_start, vma->vm_end - vma->vm_start,
                            NULL);
  KINFO("finished zapping of task (pid=%d) -> anon %ld, file %ld\n", t->pid,
        get_mm_counter(t->mm, MM_ANONPAGES),
        get_mm_counter(t->mm, MM_FILEPAGES));

  kernel_flush_tlb_current_task();

  KINFO("putting task (pid=%d) in reuse queue\n", t->pid);

  int success = 1;

  while (1) {
    ASSERT(t->state == TASK_RUNNING);
    spin_lock(&ctx->reuse_stack_lock);
    if (ctx->shutting_down) {
      spin_unlock(&ctx->reuse_stack_lock);
      success = 0;
    } else if (likely(ctx->reuse_stack_size < ctx->reuse_stack_cap)) {
      set_current_state(TASK_UNINTERRUPTIBLE);
      ctx->reuse_stack[ctx->reuse_stack_size] = t;
      ++ctx->reuse_stack_size;
      spin_unlock(&ctx->reuse_stack_lock);
    } else {
      unsigned old_cap = ctx->reuse_stack_cap;
      unsigned new_cap = old_cap ? 2 * old_cap : 4;
      spin_unlock(&ctx->reuse_stack_lock);
      struct task_struct **new_stack =
          kmalloc(new_cap * sizeof(*new_stack), GFP_KERNEL);
      struct task_struct **to_free = new_stack;
      ASSERT(new_stack != NULL);
      spin_lock(&ctx->reuse_stack_lock);
      if (likely(ctx->reuse_stack_cap == old_cap)) {
        if (ctx->reuse_stack_size > 0)
          memcpy(new_stack, ctx->reuse_stack,
                 ctx->reuse_stack_size * sizeof(*new_stack));
        ASSERT(ctx->reuse_stack == NULL || ctx->reuse_stack_cap > 0);
        to_free = ctx->reuse_stack;
        ctx->reuse_stack = new_stack;
        ctx->reuse_stack_cap = new_cap;
      }
      spin_unlock(&ctx->reuse_stack_lock);
      kfree(to_free);
      continue;
    }
    break;
  }

  if (!success) {
    KINFO("NOT putting task (pid=%d) in reuse queue, ctx is shutting down\n",
          t->pid);
    return 0;
  }

  // now run another task. wake up when we should execute another transaction.
  schedule();

  KINFO("task (pid=%d) woke up from reuse queue\n", t->pid);
  return 1;
}

static FORCE_USE struct task_struct *get_reuse_task(struct ktls_ctx *ctx) {
  struct task_struct *t = NULL;
  spin_lock(&ctx->reuse_stack_lock);
  if (likely(ctx->reuse_stack_size > 0)) {
    --ctx->reuse_stack_size;
    t = ctx->reuse_stack[ctx->reuse_stack_size];
  }
  spin_unlock(&ctx->reuse_stack_lock);
  return t;
}

static void wake_up_reused_task(struct task_struct *task) {
  ASSERT(task->state == TASK_UNINTERRUPTIBLE);
  wake_up_process(task);
}

static FORCE_USE int ktls_spawn_task(struct ktls_task *t) {
    ASSERT (current == t->ctx->parent);
    int ret = 0;

    t->task = NULL;
    t->mm = NULL;
    t->version_on_start = t->ctx->last_committed_version;
    clear_bit(KTLS_TASK_FINISHED, &t->state);
    clear_bit(KTLS_TASK_SUCCESS, &t->state);
    clear_bit(KTLS_TASK_IRREVOCABLE, &t->state);
    ktls_vector_clear(&t->touched_pages);

    struct task_struct *reuse_task = get_reuse_task(t->ctx);

    if (reuse_task == NULL) {
      clear_bit(KTLS_TASK_REUSED, &t->state);

      /*
       * Before forking, set the IP register such that we get a page fault as
       * soon as the task starts running.
       * The only address range we control right now is the stack area.
       * We set IP to the base of the second-top stack page.
       * The stack fault handler will then setup the mm, and set the IP, SP and
       * other registers to the right values.
       */
      struct pt_regs *regs = task_pt_regs(t->ctx->parent);
      unsigned long old_ip = regs->ip;

      ASSERT(t->ctx->stack_vm_addr);
      unsigned long stack_top_page = t->ctx->stack_vm_addr + CHILD_STACK_SIZE - PAGE_SIZE;
      regs->ip = stack_top_page - PAGE_SIZE;

      t->ctx->parent_stack_vma->vm_private_data = t;

      /* Important note: We set CLONE_PARENT so that the SIGCHLD gets delivered
       * to our parent, who then reaps the zombie.
       * If SIGCHLD would be delivered to the main process, then forking more
       * children after the first one terminated would not work, because the
       * copy_process function checks that there are no pending signals in the
       * current task...
       * Without SIGCHLD, noone would reap the zombie processes, and finally we
       * would hit the limit of child processes.
       *
       * We set CLONE_FILES, so that no copy of the file descriptors is created.
       * Instead, the same files_struct is used, and the usage counter is
       * incremented.
       * Immediately after startup (in ktls_handle_stack_fault), the task->files
       * field is reset to NULL and the usage counter is decremented again.
       */
      long fork_vnr = kernel_do_fork(
          CLONE_FILES | CLONE_FS | CLONE_IO | CLONE_PARENT | SIGCHLD,
          stack_top_page, CHILD_STACK_SIZE - PAGE_SIZE, NULL, NULL);

      // reset IP register in parent
      regs->ip = old_ip;
      t->ctx->parent_stack_vma->vm_private_data = 0;

      if (IS_ERR_VALUE(fork_vnr)) {
        if (fork_vnr == -ERESTARTNOINTR) {
          struct task_struct *p = t->ctx->parent;
          unsigned long guess = p->pending.signal.sig[0] & ~p->blocked.sig[0];
          if (guess == 0)
            guess =
                p->signal->shared_pending.signal.sig[0] & ~p->blocked.sig[0];
          if (guess)
            guess = ffz(~guess) + 1;
          KWARN("received -ERESTARTNOINTR. pending signal(s): %lx, shared: "
                "%lx, blocked: %lx; "
                "jobctl: %lx (guessing signal %ld)\n",
                p->pending.signal.sig[0],
                p->signal->shared_pending.signal.sig[0], p->blocked.sig[0],
                (unsigned long)p->jobctl, guess);
        }
        KERR("can't fork task: %ld\n", fork_vnr);
        ret = fork_vnr;
        goto out;
      }

      KINFO("forked task: seq_nr=%d, vnr=%ld (parent %d), func=0x%lx, "
            "stack=0x%lx-0x%lx\n",
            t->seq_nr, fork_vnr, current->pid, t->func, t->ctx->stack_vm_addr,
            t->ctx->stack_vm_addr + CHILD_STACK_SIZE);
    } else {
      KINFO("reusing task (pid=%d) for seq_nr=%d\n", reuse_task->pid, t->seq_nr);
      set_bit(KTLS_TASK_REUSED, &t->state);
      // setup the task to reuse
      struct pt_regs *regs = task_pt_regs(reuse_task);
      // set ip not to second-top page, but to bottom page.
      // second-top page would already be there, and not trigger a fault.
      ASSERT(t->ctx->stack_vm_addr);
      regs->ip = t->ctx->stack_vm_addr;

      struct vm_area_struct *stack_vma =
          find_vma(reuse_task->mm, t->ctx->stack_vm_addr);
      ASSERT(stack_vma != NULL);
      KINFO("found stack vma: %lx-%lx\n", stack_vma->vm_start, stack_vma->vm_end);
      ASSERT(stack_vma->vm_start == t->ctx->stack_vm_addr);
      ASSERT(stack_vma->vm_end == t->ctx->stack_vm_addr + CHILD_STACK_SIZE);
      ASSERT(stack_vma->vm_ops == &ktls_vm_stack_operations);
      stack_vma->vm_private_data = t;

      smp_mb();

      wake_up_reused_task(reuse_task);
    }

    /* update statistics */
    ++t->ctx->stats.num_tasks;

    /* success! */
    return 0;

out:
    return ret;
}

/*
 * don't hold any mmap_sem for read or write when calling this function.
 *
 * Return 1 on conflict, 0 on success (no conflict).
 */
static FORCE_USE int ktls_check_conflict(struct ktls_task *task) {
  struct ktls_hhash *pfn_versions = &task->ctx->pfn_versions;

  /* Check for conflicts: check all pages (read + written) against the version
   * map. */
  ASSERT(task->touched_pages.size % 2 == 0);
  for (unsigned touched_page_nr = 0; touched_page_nr < task->touched_pages.size;
       touched_page_nr += 2) {
    unsigned long addr = ktls_vector_get(&task->touched_pages, touched_page_nr);
    ASSERT(addr != 0 && (addr & PAGE_MASK) == addr);
    unsigned vers = ktls_hhash_get(pfn_versions, addr);
    if (vers > task->version_on_start) {
      KINFO("in task (pid=%d, seq_nr=%d): conflict on page %lx (version "
            "%d > %d)\n",
            task->task->pid, task->seq_nr, addr, vers, task->version_on_start);
      task->ctx->stats.num_touched_pages_rollbacked +=
          task->touched_pages.size / 2;
      return 1;
    }
  }

  return 0;
}

static void ktls_wait_task_complete(struct ktls_task *task) {
  while (!test_bit(KTLS_TASK_FINISHED, &task->state) &&
         (task->task == NULL || task->task->state != TASK_DEAD)) {
    schedule();
  }
}

static void ktls_wait_till_version(struct ktls_ctx *ctx, unsigned seq_nr) {
  struct ktls_task *waitee = NULL;
  for (struct ktls_task *t = ctx->tasks, *e = t + ctx->num_tasks; t != e; ++t)
    if (t->seq_nr <= seq_nr && (waitee == NULL || waitee->seq_nr < t->seq_nr))
      waitee = t;

  if (waitee == NULL) {
    KDEBUG("don't need to wait for anybody.\n");
    return;
  }

  KINFO("task (pid=%d) is waiting for task (pid=%d, seq_nr=%u) to complete.\n",
        current->pid, waitee->task->pid, waitee->seq_nr);

  ktls_wait_task_complete(waitee);
}

static void ktls_wait_task_start(struct ktls_task *task) {
  if (ACCESS_ONCE(task->task))
    return;
  // wait at most one minute
  unsigned long end_jiffies = jiffies + HZ * 60;
  while (ACCESS_ONCE(task->task) == NULL) {
    if (time_after(jiffies, end_jiffies)) {
      KERR("ERROR: task did not start running within one minute.");
      ASSERT(false && "timeout in ktls_wait_task_start");
    }
    schedule();
  }
}

/*
 * don't hold any mmap_sem for read or write when calling this function.
 *
 * Return 1 on conflict, 0 on success (no conflict).
 */
static FORCE_USE int ktls_make_irrevocable(struct ktls_task *task) {
    ASSERT (!test_bit(KTLS_TASK_IRREVOCABLE, &task->state));

    /* FIXME: this is totally broken right now. We have to wait for *all*
     * predecessors, and not just for completion, but until they all committed
     */

    if (task->seq_nr > 0)
      ktls_wait_till_version(task->ctx, task->seq_nr - 1);

    if (ktls_check_conflict(task))
        return 1;
    set_bit(KTLS_TASK_IRREVOCABLE, &task->state);

    KINFO("task (pid=%d, seq_nr=%u) is now irrevocable.\n",
            task->task->pid, task->seq_nr);

    return 0;
}

static void copy_back_task_output(struct ktls_task *task) {
  // copy over the output to the real location
  ASSERT(current == task->ctx->parent);
  ASSERT(access_ok(VERIFY_WRITE, task->output_addr, task->output_size));
  char *output_ptr =
      (task->input_size + task->output_size > sizeof(task->input_output)
           ? task->more_input_output
           : task->input_output) +
      task->input_size;
  int not_copied =
      copy_to_user((void *)task->output_addr, output_ptr, task->output_size);
  if (not_copied) {
    KERR("cannot copy back output\n");
    ASSERT(false);
  }
}

/*
 * don't hold any mmap_sem for read or write when calling this function.
 */
static FORCE_USE int ktls_commit(struct ktls_task *task) {
  KINFO("committing changes by pid %d (startVersion %d, seqNr %d)\n",
        task->task->pid, task->version_on_start, task->seq_nr);

  // TODO test if sorting the touched pages makes it more efficient

  ktime_t time_before_conflict_check = ktime_get();
  if (!test_bit(KTLS_TASK_IRREVOCABLE, &task->state) &&
      ktls_check_conflict(task)) {
    task->ctx->stats.nanos_conflict_checking_fail +=
        ktime_to_ns(ktime_sub(ktime_get(), time_before_conflict_check));
    return 1;
  }
  task->ctx->stats.nanos_conflict_checking_success +=
      ktime_to_ns(ktime_sub(ktime_get(), time_before_conflict_check));

  ktime_t time_before_commit = ktime_get();

  struct mm_struct *mm = task->mm;

  /* you should not hold more than one lock, so I first take the mm->mmap_sem
   * and compute all changed pages, already clearing the PTEs.
   * Then the parent_mm->mmap_sem is taken, and the pages are inserted there.
   */
  down_write(&mm->mmap_sem);

  /* Move over changed pages, and add to version map */
  unsigned removed_anon_pages = 0;
  unsigned removed_file_pages = 0;

  struct ktls_vector mod_pages;
  ktls_vector_init(&mod_pages);

  ASSERT(task->touched_pages.size % 2 == 0);
  for (unsigned touched_page_nr = 0; touched_page_nr < task->touched_pages.size;
       touched_page_nr += 2) {
    unsigned long addr = ktls_vector_get(&task->touched_pages, touched_page_nr);
    unsigned long old_pfn =
        ktls_vector_get(&task->touched_pages, touched_page_nr + 1);

    // Get child PTE:
    struct vm_area_struct *child_vma = find_vma(mm, addr);
    ASSERT(child_vma != 0);

    unsigned int page_size = 0;
    struct page *child_page =
        kernel_follow_page_mask(child_vma, addr, 0, &page_size);
    ASSERT((page_size == 0) && "hugepages not supported!!");

    if (!child_page) {
      // FIXME this is rather inefficient, because the page which is made
      // available is discarded anyway
      kernel_handle_mm_fault(mm, child_vma, addr, 0);
      child_page = kernel_follow_page_mask(child_vma, addr, 0, &page_size);
    }

    spinlock_t *child_ptl = 0;
    pte_t *child_pte = get_pte_if_present(mm, addr, &child_ptl);
    ASSERT(child_pte);
    ASSERT(pte_present(*child_pte));
    ASSERT(!pte_special(*child_pte));
    ASSERT(child_page == kernel_vm_normal_page(child_vma, addr, *child_pte));

    unsigned long child_pfn = page_to_pfn(child_page);
    ASSERT(page_mapcount(child_page) > 0);
    ASSERT(page_count(child_page) > 0);

    // Remove page from child PTE
    pte_clear(mm, addr, child_pte);

    if (PageAnon(child_page)) {
      ++removed_anon_pages;
    } else {
      ++removed_file_pages;
    }

    if (old_pfn == child_pfn) {
      // then it's a read-only access (no COW happened)

      KDEBUG("pid %d unchanged %s page at %lx (pfn %lx)\n", task->task->pid,
             PageAnon(child_page) ? "anon" : "file", addr, child_pfn);
      ASSERT(page_mapcount(child_page) > 0);
      kernel_page_remove_rmap(child_page);
      put_page(child_page);
      pte_unmap_unlock(child_pte, child_ptl);

      continue;
    }

    pte_unmap_unlock(child_pte, child_ptl);

    ktls_vector_add(&mod_pages, addr);
    ktls_vector_add(&mod_pages, (uint64_t)child_page);

    ASSERT(page_mapcount(child_page) > 0);
    ASSERT(page_count(child_page) > 0);

    ktls_hhash_add_or_update(&task->ctx->pfn_versions, addr, task->seq_nr);
  }

  // removed_anon_pages += num_mod_pages;

  // we cleared the child PTEs, so decrement the page counters
  ASSERT(get_mm_counter(mm, MM_ANONPAGES) >= removed_anon_pages);
  ASSERT(get_mm_counter(mm, MM_FILEPAGES) >= removed_file_pages);
  if (removed_anon_pages)
    add_mm_counter(mm, MM_ANONPAGES, -(long)removed_anon_pages);
  if (removed_file_pages)
    add_mm_counter(mm, MM_FILEPAGES, -(long)removed_file_pages);

  up_write(&mm->mmap_sem);

  if (mod_pages.size != 0) {
    // TODO sort mod_pages

    struct mm_struct *parent_mm = task->ctx->parent->mm;
    down_write(&parent_mm->mmap_sem);

    ASSERT(mod_pages.size % 2 == 0);
    for (unsigned mod_page_nr = 0; mod_page_nr < mod_pages.size;
         mod_page_nr += 2) {
      unsigned long addr = ktls_vector_get(&mod_pages, mod_page_nr);
      struct page *child_page =
          (struct page *)ktls_vector_get(&mod_pages, mod_page_nr + 1);

      // Get parent PTE:
      spinlock_t *parent_ptl = 0;
      struct vm_area_struct *parent_vma = find_vma(parent_mm, addr);
      ASSERT(parent_vma != 0);
      pte_t *parent_pte = get_pte_if_present(parent_mm, addr, &parent_ptl);
      ASSERT(parent_pte != 0);
      ASSERT(pte_present(*parent_pte));
      struct page *parent_page =
          kernel_vm_normal_page(parent_vma, addr, *parent_pte);
      ASSERT(parent_page || pte_special(*parent_pte));
      if (!parent_page) {
        pte_unmap_unlock(parent_pte, parent_ptl);
        // FIXME this is rather inefficient, because the page which is made
        // available is discarded anyway
        kernel_handle_mm_fault(parent_mm, parent_vma, addr, FAULT_FLAG_WRITE);
        parent_pte = get_pte_if_present(parent_mm, addr, &parent_ptl);
        parent_page = kernel_vm_normal_page(parent_vma, addr, *parent_pte);
        ASSERT(parent_page);
      }
      ASSERT(!pte_special(*parent_pte));

      // unsigned long parent_pfn = pte_pfn(*parent_pte);
      // ASSERT (parent_pfn == old_pfn && "undetected write-write conflict!");

      // KTRACE("pid %d mapping back anon page at %lx (pfn %lx) to parent,
      // discarding old pfn %lx (%s)\n",
      //        task->task->pid, addr, child_pfn, parent_pfn,
      // PageAnon(parent_page) ? "anon" : "file");

      // cp. page_move_anon_rmap
      ASSERT(page_mapcount(child_page) > 0);
      ASSERT(page_count(child_page) > 0);
      ASSERT(PageAnon(child_page));

      // DEBUG
      if (PageAnon(parent_page) &&
          (size_t)parent_page->mapping !=
              ((size_t)(find_vma(parent_mm, addr)->anon_vma) |
               PAGE_MAPPING_ANON)) {
        KWARN("WARNING: assertion will fail because parent_page->mapping "
              "is %lx, vma is %p and anon vma is %p\n",
              (size_t)parent_page->mapping, find_vma(parent_mm, addr),
              find_vma(parent_mm, addr)->anon_vma);
      }

      // ASSERT (!PageAnon(parent_page) || (size_t)parent_page->mapping ==
      // ((size_t)(find_vma(parent_mm, addr)->anon_vma) |
      // PAGE_MAPPING_ANON));

      // ASSERT (parent_page->index == ktls_page_index(find_vma(parent_mm,
      // addr), addr));

      child_page->index = parent_page->index;
      if (PageAnon(parent_page))
        child_page->mapping = parent_page->mapping;

      // Make a new PTE for insertion into the parent:
      pte_t new_pte =
          mk_pte(child_page, find_vma(parent_mm, addr)->vm_page_prot);
      new_pte = pte_mkdirty(new_pte);
      new_pte = pte_mkwrite(new_pte);
      KDEBUG("old pte: %lx; new pte: %lx   for addr %lx, pte %p\n",
             parent_pte->pte, new_pte.pte, addr, parent_pte);
      // get_page(child_page);
      set_pte_at(parent_mm, addr, parent_pte, new_pte);

      ASSERT(page_mapcount(parent_page) > 0);
      kernel_page_remove_rmap(parent_page);
      put_page(parent_page);
      pte_unmap_unlock(parent_pte, parent_ptl);
    }

    up_write(&parent_mm->mmap_sem);
  }

  copy_back_task_output(task);

  KINFO("committed all changes by pid=%d (%u touched pages, %u written)\n",
        task->task->pid, task->touched_pages.size / 2, mod_pages.size / 2);

  ++task->ctx->stats.num_commits;
  task->ctx->stats.num_read_pages += task->touched_pages.size / 2;
  task->ctx->stats.num_written_pages += mod_pages.size / 2;
  task->ctx->stats.nanos_commit +=
      ktime_to_ns(ktime_sub(ktime_get(), time_before_commit));

  ktls_vector_free(&mod_pages);

  return 0;
}

static FORCE_USE int ktls_spawn(struct ktls_ctx *ctx, struct ktls_spawn_args *spawn_args) {
    int ret = 0;

    unsigned num_tasks = spawn_args->num_tasks;
    unsigned num_cores = num_online_cpus();
    unsigned spawned_tasks = 0;
    unsigned committed_tasks = 0;

    ++ctx->stats.num_task_lists;
    for (int i = 0;
         i < num_tasks && i < sizeof(ctx->stats.num_tasks_on_position) /
                                  sizeof(*ctx->stats.num_tasks_on_position);
         ++i)
      ++ctx->stats.num_tasks_on_position[i];
    ctx->stats.num_initial_tasks += num_tasks;

    ktime_t time_before_spawns = ktime_get();

    /* allocate the ktls_tasks */
    struct ktls_task *tasks = kzalloc(num_tasks * sizeof(struct ktls_task), GFP_KERNEL);
    if (!tasks) {
        ret = -ENOMEM;
        goto out;
    }

    ctx->trampoline_task_function = (unsigned long) spawn_args->trampoline_function;
    ctx->last_committed_version = 0;
    ctx->last_started_version = 0;
    ktls_hhash_clear(&ctx->pfn_versions);

    /* read in the task information from user space */
    {
        unsigned long next_task_addr = (unsigned long) spawn_args->tasks;
        unsigned long end_task_addr = (unsigned long) spawn_args->tasks_end;
        struct ktls_task *task = tasks;
        for (unsigned i = num_tasks; i; --i, ++task) {
            struct tls_task *task_addrs = (struct tls_task *)next_task_addr;
            ASSERT ((void*)&task_addrs->input_size == (void*)&task_addrs->sizes);
            if (unlikely((unsigned long)(task_addrs + 1) > end_task_addr)) {
                ret = -EINVAL;
                goto free_tasks;
            }
            struct tls_task tls_task;
            if (!access_ok(VERIFY_WRITE, next_task_addr, sizeof(tls_task)) ||
                    __get_user(tls_task.sizes, &task_addrs->sizes) ||
                    __get_user(tls_task.function, &task_addrs->function)) {
                ret = -EFAULT;
                goto free_tasks;
            }
            unsigned long input_addr = next_task_addr + sizeof(tls_task);
            unsigned long output_addr = input_addr + tls_task.input_size;
            ret = ktls_task_init(task, &tls_task, output_addr, ctx);
            if (ret)
                goto free_tasks;
            char *input_ptr = tls_task.input_size + tls_task.output_size > sizeof(task->input_output) ?
                    task->more_input_output : task->input_output;
            if (copy_from_user(input_ptr, (void*)input_addr, tls_task.input_size)) {
                ret = -EFAULT;
                goto free_tasks;
            }
            next_task_addr = (output_addr + tls_task.output_size + 7) & ~7UL;
        }
    }

    /* Do only set tasks in the context *after* initializing the array */
    write_lock(&ktls_open_contexts_lock);
    ASSERT(ctx->tasks == NULL);
    ctx->num_tasks = num_tasks;
    ctx->tasks = tasks;
    write_unlock(&ktls_open_contexts_lock);

    if (num_tasks <= num_cores)
      KINFO("spawning %d tasks\n", num_tasks);
    else
      KINFO("spawning %d of %d tasks (rest later)\n", num_cores, num_tasks);

    // KNOTICE("parent mm before:");
    // ktls_print_mm(ctx->parent->mm);
    ret = ktls_prepare_parent_mm(ctx);
    if (ret)
        goto free_tasks;

    // this counter is also used in cleanup (on error) to know
    // which tasks are still to be released
    while (spawned_tasks < num_tasks && spawned_tasks < num_cores) {
        ret = ktls_spawn_task(tasks + spawned_tasks);
        if (ret)
            goto kill_all_tasks;
        ++spawned_tasks;
    }

    while (committed_tasks < num_tasks) {
        struct ktls_task *t = tasks + committed_tasks;
        // wait for the corresponding task to exit
        // NOTE: don't access t->task before having waited on t->finished.
        //       it might not have been set yet.
        KINFO("waiting for task (seq_nr=%d) to finish before committing\n",
              t->seq_nr);
        ktls_wait_task_complete(t);

        smp_mb();

        if (!test_bit(KTLS_TASK_FINISHED, &t->state)) {
          ASSERT(!test_bit(KTLS_TASK_SUCCESS, &t->state));
          KERR("child %u (pid=%d, seq_nr=%d) exited without finishing the user "
               "function.\n",
               committed_tasks, t->task->pid, t->seq_nr);
        }

        // See if the user function returned correctly.
        unsigned success = test_bit(KTLS_TASK_SUCCESS, &t->state);

        if (!success && t->version_on_start == t->seq_nr - 1) {
            KERR("child %u (pid %d) had no possibly conflicting predecessors, but still failed. "
                    "giving up on this task.\n", committed_tasks, t->task->pid);
            // return the number of already executed tasks plus one.
            ret = committed_tasks + 1;
            goto kill_all_tasks;
        }

        // check for conflicts and commit
        if (success && ktls_commit(t))
            success = 0;

        // release the task and the mm
        if (accu) {
            mmput(t->mm);
            put_task_struct(t->task);
        }

        // notify the task that the commit phase finished
        if (test_bit(KTLS_TASK_FINISHED, &t->state)) {
          KDEBUG("pid %d waking up process (pid=%d,seq_nr=%d) after commit\n",
                 current->pid, t->task->pid, t->seq_nr);
          ASSERT(t->task->state == TASK_UNINTERRUPTIBLE);
          wake_up_process(t->task);
        }

        if (!success) {
            /* conflict in task */
            ++ctx->stats.num_rollbacks;
            KINFO("respawning task %d (pid=%d, last seq_nr=%d, last start "
                  "version=%d)\n",
                  committed_tasks, t->task->pid, t->seq_nr, t->version_on_start);
            if (!accu) {
                mmput(t->mm);
                put_task_struct(t->task);
            }
            ret = ktls_spawn_task(t);
            if (ret) {
                ++committed_tasks; // this task does not need to be killed
                goto kill_all_tasks;
            }
            if (committed_tasks < sizeof(ctx->stats.succeeding_tasks) /
                                      sizeof(*ctx->stats.succeeding_tasks))
              --ctx->stats.succeeding_tasks[committed_tasks];
            continue;
        }

        if (committed_tasks < sizeof(ctx->stats.succeeding_tasks) /
                                  sizeof(*ctx->stats.succeeding_tasks))
          ++ctx->stats.succeeding_tasks[committed_tasks];

        ASSERT(ctx->last_committed_version < t->seq_nr);
        ASSERT(t->seq_nr <= ctx->last_started_version);
        ctx->last_committed_version = t->seq_nr;

        ++committed_tasks;

        ktls_free_task(t);

        // if not all tasks are spawned yet, spawn the next one
        if (spawned_tasks < num_tasks) {
          ret = ktls_spawn_task(tasks + spawned_tasks);
          if (ret)
            goto kill_all_tasks;
          ++spawned_tasks;
        }
    }
    KINFO("all tasks terminated\n");

    // FIXME test performance of flushing the individual pages, maybe with a threshold of pages
    kernel_flush_tlb_current_task();

    goto free_tasks;

kill_all_tasks:
    // oh, oh, something went really wrong. kill the already started tasks.
    for (unsigned i = committed_tasks; i < spawned_tasks; ++i) {
        ktls_wait_task_start(&tasks[i]);
        ASSERT (tasks[i].task);
        if (tasks[i].task->state != TASK_DEAD) {
            force_sig(SIGKILL, tasks[i].task);
        }
    }
    for (unsigned i = committed_tasks; i < spawned_tasks; ++i) {
        if (tasks[i].task) {
            kernel_wait_task_inactive(tasks[i].task, 0);
            mmput(tasks[i].mm);
            put_task_struct(tasks[i].task);
        }
    }

free_tasks:
    /* unlink tasks from context */
    write_lock(&ktls_open_contexts_lock);
    ctx->num_tasks = 0;
    ctx->tasks = NULL;
    write_unlock(&ktls_open_contexts_lock);

    KDEBUG("Freeing tasks!\n");
    if (!accu) {
      for (unsigned i = 0; i < num_tasks; ++i) {
        struct ktls_task *t = tasks + i;
        mmput(t->mm);
        put_task_struct(t->task);
        ktls_free_task(t);
      }
    }
    kfree(tasks);

    int ret2 = ktls_reset_parent_mm(ctx);
    if (ret2 && !ret)
        ret = ret2;

out:
    ctx->stats.nanos_total_task_list +=
        ktime_to_ns(ktime_sub(ktime_get(), time_before_spawns));
    return ret;
}


static struct ktls_task *ktls_find_task(struct task_struct *t) {
    read_lock(&ktls_open_contexts_lock);

    struct ktls_task *found_task = NULL;
    for (struct ktls_ctx **ctxp = ktls_open_contexts, **ctx_end = ctxp+ktls_num_open_contexts;
            ctxp != ctx_end; ++ctxp)
        for (struct ktls_task *task = (*ctxp)->tasks, *task_end = task+(*ctxp)->num_tasks;
                task != task_end; ++task)
            if (ACCESS_ONCE(task->task) == t) {
                found_task = task;
                goto unlock;
            }

unlock:
    read_unlock(&ktls_open_contexts_lock);

    return found_task;
}


/**
 * This function is called with non-exclusive mmap_sem, and also returns
 * with mmap_sem held.
 */
static int ktls_handle_fault(struct vm_area_struct *vma, struct vm_fault *vmf) {

    unsigned long address = (unsigned long) vmf->virtual_address;
    ASSERT ((address & ~PAGE_MASK) == 0);
    int is_write = (vmf->flags & FAULT_FLAG_WRITE) != 0;

    smp_mb();
    struct ktls_task *task = ktls_get_task(vma);
    struct task_struct *parent = task->ctx->parent;

    KDEBUG("fault: pid(%d), anon(%ld), file(%ld), ip(0x%lx), addr(0x%lx), "
           "flags(%x) -> write(%d)\n",
           current->pid, get_mm_counter(vma->vm_mm, MM_ANONPAGES),
           get_mm_counter(vma->vm_mm, MM_FILEPAGES), task_pt_regs(current)->ip,
           address, vmf->flags, is_write);

    ASSERT(task->task != NULL);
    // this method can be called from the task itself, or from the parent during
    // commit (which can potentially be optimized...)
    ASSERT(task->task == current || task->task == parent);

    /* follow_page_mask does everything to make the page available,
     * and FOLL_GET ensures that the page is "locked" (usage counter increased)
     */
    struct mm_struct *parent_mm = parent->mm;
    down_read(&parent_mm->mmap_sem);
    struct vm_area_struct *parent_vma = find_vma(parent_mm, address);
    ASSERT (parent_vma);
    unsigned int page_size;
    // TODO test if it is faster to try get_pte_if_present first
    struct page *parent_page = kernel_follow_page_mask(parent_vma, address, FOLL_GET, &page_size);
    if (!parent_page) {
        int ret = kernel_handle_mm_fault(parent_mm, parent_vma, address, 0);
        if (ret & VM_FAULT_ERROR) {
            KERR("ERROR: pid %d trying to access invalid address %lx (mm_fault returned %d).\n", current->pid, address, ret);
            up_read(&parent_mm->mmap_sem);
            return VM_FAULT_SIGBUS;
        } else {
            parent_page = kernel_follow_page_mask(parent_vma, address, FOLL_GET, &page_size);
            if (!parent_page) {
                KERR("ERROR: in pid %d: page (addr %lx) still not available after triggering page fault.\n", current->pid, address);
                up_read(&parent_mm->mmap_sem);
                return VM_FAULT_SIGBUS;
            }
        }
    }
    up_read(&parent_mm->mmap_sem);
    ASSERT ((page_size == 0) && "hugepages not supported!!");

    /*
    KTRACE("parent page: %p (pfn %lu, addr 0x%lx, %s)\n",
            parent_page, parent_pfn, parent_pfn << PAGE_SHIFT,
            PageAnon(parent_page) ? "anon" : "file");
    */

    /* log page access */

    /* log start version on first memory access */
    if (task->touched_pages.size == 0)
      task->version_on_start = task->ctx->last_committed_version;
    ktls_vector_add(&task->touched_pages, address);
    ktls_vector_add(&task->touched_pages, page_to_pfn(parent_page));

    vmf->page = parent_page;

    /* this fixes a "bug" in memory.c: It always assumes the returned page to be
     * a "file" page, thus sometimes incrementing the wrong counter.
     */
    if (!is_write && PageAnon(parent_page)) {
        inc_mm_counter(task->mm, MM_ANONPAGES);
        dec_mm_counter(task->mm, MM_FILEPAGES);
    }

    lock_page(parent_page);
    //put_page(parent_page);

    return VM_FAULT_LOCKED;
}

static int ktls_handle_stack_fault(struct vm_area_struct *vma, struct vm_fault *vmf) {

    unsigned long address = (unsigned long) vmf->virtual_address;
    int is_write = (vmf->flags & FAULT_FLAG_WRITE) != 0;

    KDEBUG("stack fault: pid(%d), addr(0x%lx), pgoff(%lu), flags(%x) -> write(%d)\n",
            current->pid, address, vmf->pgoff, vmf->flags, is_write); (void)is_write;

    struct ktls_task *t = ktls_get_task(vma);

    /**
     * When forked, the IP of the child is set to the start of the top page.
     * Thus, we immediately end up in this fault handler.
     *
     * Reused tasks already have a stack top page, and we do not want to
     * unnecessarily remove it, so reused tasks get their IP set to the start of
     * the last stack page.
     *
     * In either case, this handler sets up the registers to execute the actual
     * user code.
     * Also, we set up the mm, and copy over the inputs to the second-top stack page.
     * It will contain (from top): outputs, inputs, returnIP, <normal stack>.
     * returnIP will point to the top stack page, so when we get a page fault there,
     * we know that the child has finished executing the task function.
     */

    // FIXME handle input/output greater PAGE_SIZE by copying the remaining input
    //       to the other pages when they are requested
    ASSERT(t->input_size + t->output_size <= PAGE_SIZE);

    bool is_first_fault = t->task == 0;
    ASSERT(!is_first_fault || address == test_bit(KTLS_TASK_REUSED, &t->state)
               ? t->ctx->stack_vm_addr
               : t->ctx->stack_vm_addr + CHILD_STACK_SIZE - 2 * PAGE_SIZE);

    if (is_first_fault) {
        t->task = current;
        t->mm = t->task->mm;
        smp_mb();

        KDEBUG("first stack fault of (pid=%d, seq_nr=%d), setting up registers "
               "and mm\n",
               t->task->pid, t->seq_nr);

        struct pt_regs *regs = task_pt_regs(t->task);
        ASSERT(regs->ip == address);

        unsigned long top_page = t->ctx->stack_vm_addr + CHILD_STACK_SIZE - PAGE_SIZE;
        regs->sp = top_page - t->input_size - t->output_size;
        regs->bp = regs->sp;

        regs->ip = t->ctx->trampoline_task_function;
        regs->di = top_page - t->input_size - t->output_size; /* 1st arg = input struct */
        regs->si = top_page - t->output_size; /* 2nd arg = output struct */
        regs->dx = t->func; /* 3rd arg = function to execute */
        regs->cx = t->input_size + t->output_size; /* 4th arg = reserved stack size */

        // ensure that this task and its mm stay alive after execution:
        get_task_struct(t->task);
        atomic_inc(&t->mm->mm_users);

        unsigned reused = test_bit(KTLS_TASK_REUSED, &t->state);
        if (reused) {
          KINFO("adjusting already set-up mm %p of reused task (pid=%d, "
                "seq_nr=%d)\n",
                t->mm, t->task->pid, t->seq_nr);
          for (struct vm_area_struct *vma2 = t->mm->mmap; vma2;
               vma2 = vma2->vm_next) {
            if (vma2->vm_ops == &ktls_vm_operations)
              vma2->vm_private_data = t;
          }

          // copy input to the top stack page (is already allocated from earlier
          // task)
          if (t->input_size > 0) {
            KDEBUG("copying input to task (pid=%d, seq_nr=%d)\n", t->task->pid,
                   t->seq_nr);
            void *input_ptr =
                t->input_size + t->output_size > sizeof(t->input_output)
                    ? t->more_input_output
                    : t->input_output;
            void *dst_ptr = (void *)(top_page - t->output_size - t->input_size);
            unsigned not_copied =
                copy_to_user(dst_ptr, input_ptr, t->input_size);
            ASSERT(not_copied == 0 && "copy task input to reused task");
            (void)not_copied;
          }
        } else {
          int ret = ktls_mm_setup(t);
          if (ret) {
            KDEBUG("ERROR setting up the mm (code %d)\n", ret);
            return VM_FAULT_SIGBUS;
          }

          // Release the files struct of this task.
          ASSERT(t->task->files != NULL);
          kernel_exit_files(t->task);
          ASSERT(t->task->files == NULL);
        }

        t->time_start = ktime_get();

        if (reused)
          return VM_FAULT_NOPAGE;
    }

    ASSERT (t->task == current);

    if (address == t->ctx->stack_vm_addr + CHILD_STACK_SIZE - PAGE_SIZE) {
        KINFO("child(pid=%d, seq_nr=%d) returned from user function.\n",
              t->task->pid, t->seq_nr);
        t->ctx->stats.num_tasks_returned_from_user_function++;
        t->ctx->stats.nanos_user_code +=
            ktime_to_ns(ktime_sub(ktime_get(), t->time_start));
        if (t->output_size > 0) {
            char *ptr = (t->input_size + t->output_size > sizeof(t->input_output) ?
                    t->more_input_output : t->input_output) + t->input_size;
            unsigned not_copied = copy_from_user(ptr,
                    (char*)t->ctx->stack_vm_addr + CHILD_STACK_SIZE - PAGE_SIZE - t->output_size,
                    t->output_size);
            if (not_copied) {
                KERR("cannot copy back output\n");
                ASSERT (false);
            }
        }
        struct task_struct *cur = t->task;
        up_read(&cur->mm->mmap_sem);
        ASSERT(!test_bit(KTLS_TASK_FINISHED, &t->state));
        ASSERT(!test_bit(KTLS_TASK_SUCCESS, &t->state));
        set_bit(KTLS_TASK_SUCCESS, &t->state);
        // sleep until commit_finished is set. parent will wake us up.
        // set state to sleeping before setting the finished flag, to avoid
        // race conditions.
        ASSERT(cur->state == TASK_RUNNING);
        KDEBUG("task (pid=%d, seq_nr=%d) sleeping till commit has happened\n",
               cur->pid, t->seq_nr);
        set_current_state(TASK_UNINTERRUPTIBLE);
        smp_wmb();
        struct ktls_ctx *ctx = t->ctx;
        // increment the ctx usage counter such that it stays alive during our
        // sleep
        ktls_get_ctx(ctx);

        set_bit(KTLS_TASK_FINISHED, &t->state);

        // after setting the finished flag, we are not allowed to touch the task
        // any more, since the parent might have freed it in the meantime.

        // now sleep until the parent wakes us up...
        schedule();
        KDEBUG("task (pid=%d) woke up\n", cur->pid);
        int shutdown = !put_task_in_reuse_queue(cur, ctx);
        smp_mb();
        shutdown |= ctx->shutting_down;
        ktls_put_ctx(ctx);
        if (shutdown) {
          KINFO("ctx shutting down, exiting task pid=%d\n", cur->pid);
          do_exit(0);
        }
        down_read(&cur->mm->mmap_sem);
        // the one who woke us up has already set up everything for execution.
        // return VM_FAULT_NOPAGE, so that the task just continues execution.
        return VM_FAULT_NOPAGE;
    } else if (address == t->ctx->stack_vm_addr) {
        KERR("ERROR: child(%d) uses lowest stack page. consider making the stack larger.\n", t->task->pid);
        return VM_FAULT_SIGBUS;
    }

    /* allocate a new empty page */
    struct page *stack_page = alloc_pages(GFP_KERNEL, 0);
    if (!stack_page)
        return VM_FAULT_OOM;

    //get_page(stack_page);
    stack_page->mapping = 0;

    if (is_first_fault && t->input_size > 0) {
        void *input_ptr = t->input_size + t->output_size > sizeof(t->input_output)
                ? t->more_input_output : t->input_output;
        void *stack_page_vaddr = kmap(stack_page);
        memcpy(stack_page_vaddr + PAGE_SIZE - t->output_size - t->input_size, input_ptr, t->input_size);
        kunmap(stack_page);
    }

    lock_page(stack_page);

    KDEBUG("allocated stack page for addr 0x%lx (vaddr=0x%p, paddr=0x%llx, page=%p, pfn=%lx)\n",
            address, phys_to_virt(page_to_phys(stack_page)), page_to_phys(stack_page), stack_page,
            page_to_pfn(stack_page));

    vmf->page = stack_page;

    return VM_FAULT_LOCKED;
}

/* non-static, because called from assembly (see syscalls.h) */
void ktls_syscall_irrevocable(unsigned syscall_nr) {
  struct task_struct *t = current;
  struct ktls_task *task = ktls_find_task(t);
  if (task == NULL)
    return;

  if (test_bit(KTLS_TASK_IRREVOCABLE, &task->state)) {
    KDEBUG("another syscall (%d) inside irrevocable transaction (pid=%d, "
           "seq_nr=%d)\n",
           syscall_nr, t->pid, task->seq_nr);
    return;
  }

  KINFO("first syscall (%d) inside transaction (pid=%d, seq_nr=%d)!! trying to "
        "make this task irrevocable.\n",
        syscall_nr, t->pid, task->seq_nr);

  if (ktls_make_irrevocable(task)) {
    ++task->ctx->stats.num_irrevocable_tasks;
    ASSERT(!test_bit(KTLS_TASK_FINISHED, &t->state));
    ASSERT(!test_bit(KTLS_TASK_SUCCESS, &t->state));
    do_exit(0);
    ASSERT(false && "should not be reached");
  }
}

/* non-static, because called from assembly (see syscalls.h) */
void ktls_syscall_forbidden(unsigned syscall_nr) {
    struct task_struct *t = current;
    struct ktls_task *task = ktls_find_task(t);
    if (task == NULL)
        return;

    KNOTICE("executing dangerous syscall (%d) inside transaction (pid=%d, "
            "seq_nr=%d, ip=%lx). aborting.\n",
            syscall_nr, t->pid, task->seq_nr, task_pt_regs(t)->ip);
    ASSERT(!test_bit(KTLS_TASK_FINISHED, &t->state));
    ASSERT(!test_bit(KTLS_TASK_SUCCESS, &t->state));
    ++task->ctx->stats.num_forbidden_syscalls;
    // TODO check whether we can reuse this task (it's in the middle of a
    // syscall handler)
    do_exit(1);
    ASSERT (false && "should not be reached");
}

static void ktls_cleanup_contexts(void) {
  unsigned processed = 0;
  while (1) {
    struct ktls_ctx *ctx = NULL;
    read_lock(&ktls_open_contexts_lock);
    unsigned num_ctx = ktls_num_open_contexts;
    while (processed < num_ctx) {
      struct ktls_ctx *cand = ktls_open_contexts[processed];
      if (cand->parent->state == TASK_DEAD && !cand->shutting_down) {
        ctx = cand;
        ktls_get_ctx(ctx);
        break;
      }
      ++processed;
    }
    read_unlock(&ktls_open_contexts_lock);
    if (ctx == NULL)
      break;
    KINFO("ktls cleanup by pid %d is finishing context %p\n", current->pid,
          ctx);
    ktls_shutdown_ctx(ctx);
    ktls_put_ctx(ctx);
  }
}

static int ktls_cleanup_thread_fn(void *data) {
  while (!kthread_should_stop()) {
    ktls_cleanup_contexts();
    msleep_interruptible(1000);
  }
  return 0;
}

static FORCE_USE int ktls_add_open_context(struct ktls_ctx *ctx) {
  ASSERT(atomic_read(&ctx->ref_count) > 0);
  for (int try = 0;; ++try) {
    int max_contexts = 0;
    int shutting_down = 0;
    write_lock(&ktls_open_contexts_lock);
    if (ktls_shutting_down) {
      shutting_down = 1;
    } else if (ktls_num_open_contexts == KTLS_MAX_CONTEXTS) {
      max_contexts = 1;
    } else {
      ktls_open_contexts[ktls_num_open_contexts++] = ctx;
    }
    write_unlock(&ktls_open_contexts_lock);

    if (shutting_down) {
      KERR("cannot register new context: ktls is shutting down\n");
      return 1;
    }
    if (!max_contexts)
      return 0;
    if (try > 0) {
      KERR("ERROR: maximum number of contexts (%d) exceeded\n",
           KTLS_MAX_CONTEXTS);
      return 1;
    }
    ktls_cleanup_contexts();
  }
}

// allocate a new context and set ref counter to 1.
static FORCE_USE struct ktls_ctx *ktls_new_ctx(void) {
    struct ktls_ctx *ctx = kzalloc(sizeof(struct ktls_ctx), GFP_KERNEL);

    if (ctx == NULL) {
        KERR("error allocating new context for pid %d\n", current->pid);
        return ERR_PTR(-ENOMEM);
    }

    KINFO("opening context %p (pid %d, name '%s')\n", ctx, current->pid, current->comm);

#ifndef NDEBUG
    ctx->magic = KTLS_MAGIC;
#endif
    ctx->parent = current;

    ktls_hhash_new(&ctx->pfn_versions);

    spin_lock_init(&ctx->reuse_stack_lock);

    atomic_set(&ctx->ref_count, 1);

    // increase usage counter of parent task, is decreased when context is
    // destroyed
    get_task_struct(ctx->parent);

    // register context in the list of open contexts
    if (ktls_add_open_context(ctx))
      goto error;

    return ctx;

error:
    kfree(ctx);
    return 0;
}

/**
 * Prepare the shutdown by setting the shutting_down flag to 1, and waking up
 * all reuse tasks. The last reuse task which exits will then really free the
 * context.
 */
static void ktls_shutdown_ctx(struct ktls_ctx *ctx) {
  KINFO("pid %d shutting down context %p\n", current->pid, ctx);

  unsigned was_shutting_down = 0;
  write_lock(&ktls_open_contexts_lock);
  // also take the reuse_stack_lock such that we synchronize with
  // put_task_in_reuse_queue
  spin_lock(&ctx->reuse_stack_lock);
  was_shutting_down = ctx->shutting_down;
  ctx->shutting_down = 1;
  if (!was_shutting_down) {
    unsigned num_ctx = ktls_num_open_contexts;
    unsigned idx = 0;
    while (idx < num_ctx && ktls_open_contexts[idx] != ctx)
      ++idx;
    if (idx < num_ctx - 1)
      ktls_open_contexts[idx] = ktls_open_contexts[num_ctx - 1];
    else if (idx != num_ctx - 1)
      KERR("ERROR: context not in list of open contexts\n");
    ktls_num_open_contexts = num_ctx - 1;
  }
  spin_unlock(&ctx->reuse_stack_lock);
  write_unlock(&ktls_open_contexts_lock);

  if (was_shutting_down) {
    KDEBUG("pid %d NOT shutting down context %p, is already shutting down\n",
           current->pid, ctx);
    return;
  }

  struct task_struct *reuse_task;
  while ((reuse_task = get_reuse_task(ctx)) != NULL) {
    KINFO("killing reuse task pid=%d\n", reuse_task->pid);
    wake_up_reused_task(reuse_task);
  }
}

static void ktls_free_ctx(struct ktls_ctx *ctx) {
    if (!ctx->shutting_down)
      ktls_shutdown_ctx(ctx);

    ktls_hhash_delete(&ctx->pfn_versions);

    if (ctx->reuse_stack_cap > 0)
      kfree(ctx->reuse_stack);

    put_task_struct(ctx->parent);

    ASSERT(ctx->last_committed_version <= ctx->last_started_version);
    KINFO("freeing context %p (by pid %d)\n", ctx, current->pid);
    kfree(ctx);
}

static void ktls_get_ctx(struct ktls_ctx *ctx) {
#ifndef NDEBUG
  int new_val = atomic_inc_return(&ctx->ref_count);
  ASSERT(new_val > 1 && "must not increment from zero");
#else
  atomic_inc(&ctx->ref_count);
#endif
}

static void ktls_put_ctx(struct ktls_ctx *ctx) {
  if (atomic_dec_and_test(&ctx->ref_count))
    ktls_free_ctx(ctx);
}

static int ktls_dev_open(struct inode *inode, struct file *file) {
    struct ktls_ctx *ctx = ktls_new_ctx();
    if (IS_ERR(ctx))
        return PTR_ERR(ctx);

    file->private_data = ctx;

    return 0;
}

static int ktls_dev_release(struct inode *inode, struct file *filp) {
    struct ktls_ctx *ctx = ktls_ctx_from_file(filp);

    if (ctx == NULL)
        return -EIO;

    KDEBUG("pid %d releases context %p\n", current->pid, ctx);

    // if this is the parent, initiate shutdown
    if (current == ctx->parent)
      ktls_shutdown_ctx(ctx);

    ktls_put_ctx(ctx);

    return 0;
}

static ssize_t ktls_dev_read(struct file *filp, char __user *buf, size_t len, loff_t __user *off) {
  return 0;
}

static ssize_t ktls_dev_write(struct file *filp, const char __user *buf, size_t len, loff_t __user *off) {
  return 0;
}

/* IOCTLs */
static long ktls_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct ktls_ctx *ctx = ktls_ctx_from_file(filp);

    if (ctx == NULL)
        return -EIO;

    if (ctx->parent != current)
        return -EACCES;

    long ret = 0;

    KDEBUG("device ioctl; ctx=%p, cmd=%d, arg=0x%08lX\n", ctx, cmd, arg);

    struct ktls_spawn_args spawn_args;

    switch (cmd) {
    case KTLS_IOCTL_SPAWN:
        if (!ret && !access_ok(VERIFY_READ, arg, sizeof(spawn_args))) {
            ret = -EFAULT;
            KINFO("cannot read spawn_args, returning -EFAULT");
        }
        if (!ret && copy_from_user(&spawn_args, (struct ktls_spawn_args*)arg, sizeof(spawn_args))) {
            ret = -EFAULT;
            KINFO("cannot copy spawn_args, returning -EFAULT");
        }
        size_t tasks_size = spawn_args.tasks_end - spawn_args.tasks;
        if (!ret && (tasks_size > 1024*1024 || spawn_args.num_tasks > 1024)) {
            ret = -E2BIG;
            KINFO("too many tasks (num %u, size %zu), returning -E2BIG",
                    spawn_args.num_tasks, tasks_size);
        }
        if (!ret)
            ret = ktls_spawn(ctx, &spawn_args);
        break;
    case KTLS_IOCTL_STATS:
        KINFO("retrieving KTLS stats\n");
        if (copy_to_user((void*)arg, &ctx->stats, sizeof(struct ktls_stats)))
            ret = -EFAULT;
        break;
    case KTLS_IOCTL_RESET_STATS:
        KINFO("resetting KTLS stats\n");
        memset(&ctx->stats, 0, sizeof(ctx->stats));
        break;
    default:
        ret = -EINVAL;
    }

    return ret;
}

static void __init *ktls_find_kernel_symbol(const char *name, int *ret) {
  void *fn = (void *)kallsyms_lookup_name(name);
  if (!fn) {
    KERR("Did not find kernel symbol named '%s'. Ensure that KALLSYMS is "
         "configured for your kernel.",
         name);
    *ret = -EPERM;
  }
  return fn;
}

int __init ktls_init(void) {
    int ret = 0;
    int max_debug;
#ifndef NDEBUG
#define ASSERT_EN "en"
    max_debug = 4;
#else
#define ASSERT_EN "dis"
    max_debug = 2;
#endif
#define xstr(s) str(s)
#define str(s) #s
    KNOTICE("Initializing (debug level = %d, assertions " ASSERT_EN "abled (" xstr(BUILDMODE) "))\n", debug);
    if (debug < 0 || debug > max_debug)
        KWARN("Illegal debug level (%d) for this configuration. Valid range: 0-%d\n",
                debug, max_debug);

    KINFO("Collecting kernel symbols through kallsyms_lookup_name\n");
    KERNEL_SYMBOLS(INIT_KERNEL_FUNC_OR_SYM, INIT_KERNEL_FUNC_OR_SYM)
    if (ret)
        goto out;

    KINFO("Registering device: %s\n", KTLS_DEV_NAME);
    if (!ret) {
        ret = alloc_chrdev_region(&ktls_dev_chrdev, 0, 1, KTLS_DEV_NAME);
        if (unlikely(ret))
            goto out;
        ktls_dev_class = class_create(THIS_MODULE, "chardrv");
        if (unlikely(IS_ERR_OR_NULL(ktls_dev_class))) {
            ret = PTR_ERR(ktls_dev_class);
            goto unreg_chrdev;
        }
        ktls_dev_device = device_create(ktls_dev_class, NULL, ktls_dev_chrdev, NULL, KTLS_DEV_NAME);
        if (unlikely(IS_ERR_OR_NULL(ktls_dev_device))) {
            ret = PTR_ERR(ktls_dev_device);
            goto unreg_class;
        }
        cdev_init(&ktls_dev_cdev, &ktls_dev_fops);
        ktls_dev_cdev.owner = THIS_MODULE;
        ret = cdev_add (&ktls_dev_cdev, ktls_dev_chrdev, 1);
        if (ret) {
            KERR("Error adding chardev for ktls\n");
            goto unreg_device;
        }
        goto dev_ready;

unreg_device:
        device_destroy(ktls_dev_class, ktls_dev_chrdev);
unreg_class:
        class_destroy(ktls_dev_class);
unreg_chrdev:
        unregister_chrdev_region(ktls_dev_chrdev, 1);
        goto out;
    }
dev_ready:

    rwlock_init(&ktls_open_contexts_lock);
    KINFO("Redirecting system calls\n");
    ktls_redirect_system_calls(kernel_sys_call_table, kernel_set_memory_rw);

    ktls_ctx_cleanup_thread =
        kthread_run(ktls_cleanup_thread_fn, NULL, "ktls_cleanup");
    KINFO("Started cleanup thread (pid=%d)\n", ktls_ctx_cleanup_thread->pid);

out:
    return ret;
}

void __exit ktls_exit(void) {
  KNOTICE("Shutting down KTLS...\n");

  ASSERT(ktls_shutting_down == 0);
  write_lock(&ktls_open_contexts_lock);
  ktls_shutting_down = 1;
  unsigned open_ctxs = ktls_num_open_contexts;
  write_unlock(&ktls_open_contexts_lock);

  KINFO("shutting down the context cleanup thread (pid=%d)\n",
        ktls_ctx_cleanup_thread->pid);
  kthread_stop(ktls_ctx_cleanup_thread);

  unsigned last_open_ctxs = 0;
  while (open_ctxs != 0) {
    if (open_ctxs != last_open_ctxs) {
      KWARN("waiting for %d open contexts to close before shutting down...\n",
            open_ctxs);
    }
    last_open_ctxs = open_ctxs;
    ktls_cleanup_contexts();
    schedule();
    read_lock(&ktls_open_contexts_lock);
    open_ctxs = ktls_num_open_contexts;
    read_unlock(&ktls_open_contexts_lock);
  }

  ktls_restore_system_calls(kernel_sys_call_table);

  cdev_del(&ktls_dev_cdev);
  device_destroy(ktls_dev_class, ktls_dev_chrdev);
  class_destroy(ktls_dev_class);
  unregister_chrdev_region(ktls_dev_chrdev, 1);

  KINFO("finished shutdown of KTLS.\n");
}


module_init(ktls_init)
module_exit(ktls_exit)
