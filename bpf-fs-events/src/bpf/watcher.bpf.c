#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*  NAME_MAX is a reasonable name length limit from 'fs/ext4/ext4.h'.
    Except, this is 256, not 255, because we want to align on 8-byte
    boundary. Else the reader in userspace would have to do some extra
    work. Also, we have no need for a null terminator, or a need to
    shove a bit of data into the last byte. We can just align it.

    We apply this to a path component's name, not the full pathname.
    We can read at most a NAME_MAX*SUBPATH_DEPTH_MAX length pathname.
    (PATH_MAX is usually where the full pathname limit is enforced,
    but not always. I don't think it's enforced by the ext4 fs.)

    ... Actually, I'm not sure. Maybe PT_MAX (4096) is a fine limit.
    Plenty of other tools will stop at PT_MAX. Maybe it's fine.
    But then again a (maybe malicious) program under watch by this
    tool could probably be undetected under a path longer than PT_MAX.
    (They could also be undetected if we aren't efficient enough to
    catch all the events, or if the kernel drops something.) So, we'll
    stick with the common PT_MAX limit for now.
*/
#define NAME_MAX 256
#define SUBPATH_DEPTH_MAX 128
#define COMMON_PATH_MAX 4096
#define BUF_MAX (COMMON_PATH_MAX * 32)
#define ALIGNED_EVENT_BUF_MAX (NAME_MAX / sizeof(u64))

#define U32_MAX 0xFFFFFFFF
#define FMODE_CREATED 0x100000

/*  Stat, inode flags
    1. [Inode docs, not ext4-specific]
       (https://www.kernel.org/doc/html/latest/filesystems/ext4/inodes.html)
    2. [inode(7)]
       (https://www.man7.org/linux/man-pages/man7/inode.7.html) */
#define S_IFIFO 0x1000   // FIFO
#define S_IFCHR 0x2000   // Character device
#define S_IFDIR 0x4000   // Directory
#define S_IFBLK 0x6000   // Block device
#define S_IFREG 0x8000   // Regular file
#define S_IFLNK 0xA000   // Symbolic link
#define S_IFSOCK 0xC000  // Socket
#define S_IFMT 00170000  // Mask on mode to get at the above ^

#define ALLOW_TRACE_LOG 0
#define ALLOW_DEBUG_LOG 0
#define ALLOW_INFO_LOG 0
#define ALLOW_WARN_LOG 1
#define ALLOW_ERROR_LOG 1

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memset(dest, val, n) __builtin_memset((dest), (val), (n))
#define event_submit(event) bpf_ringbuf_submit(event, 0)
#define exposed_in_btf(typename) _##typename = {0};
#define read_len(dst, len, src) bpf_probe_read_kernel(dst, len, src)
#define read_ptr(dst, src) read_len(dst, sizeof(dst), src)
#define read_concrete(dst, src) read_len(dst, sizeof(*dst), src)

#if ALLOW_TRACE_LOG
#define tlog(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define tlog(fmt, ...)
#endif
#if ALLOW_DEBUG_LOG
#define dlog(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dlog(fmt, ...)
#endif
#if ALLOW_INFO_LOG
#define ilog(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define ilog(fmt, ...)
#endif
#if ALLOW_WARN_LOG
#define wlog(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define wlog(fmt, ...)
#endif
#if ALLOW_ERROR_LOG
#define elog(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define elog(fmt, ...)
#endif

// For 'preserve_access_index'
#pragma clang diagnostic ignored "-Wunknown-attributes"

/*  Enums (and some other types with unspecified bit patterns or pdding)
    are awkward and sometimes unsafe to use between languages.
    Best to use basic numeric types and constants. */
static const u8 PT_DIR = 0;
static const u8 PT_FILE = 1;
static const u8 PT_SYMLINK = 2;
static const u8 PT_HARDLINK = 3;
static const u8 PT_BLOCK = 4;
static const u8 PT_SOCKET = 5;
static const u8 PT_UNKNOWN = 6;
static const u8 PT_CONT = 7;

static const u8 ET_CREATE = 0;
static const u8 ET_RENAME = 1;
static const u8 ET_LINK = 2;
static const u8 ET_DELETE = 3;
static const u8 ET_CONT = 4;
static const u8 ET_ASSOC = 5;

/*
enum effect_type {
    ET_CREATE,
    ET_RENAME,
    ET_LINK,
    ET_DELETE,
    ET_CONT,
    ET_ASSOC,
} exposed_in_btf(effect_type);

enum path_type {
    PT_DIR,
    PT_FILE,
    PT_SYMLINK,
    PT_HARDLINK,
    PT_BLOCK,
    PT_SOCKET,
    PT_UNKNOWN,
    PT_CONT,
} exposed_in_btf(path_type);
*/

/*  pahole is our friend. */
struct event {
    u64 timestamp;
    u32 pid;
    u16 buf_len;
    u16 event_group_id;
    u8 effect_type;
    u8 path_type;
    /*  We'll align the buffer on an 8 byte boundary. */
    u64 buf[ALIGNED_EVENT_BUF_MAX];
} exposed_in_btf(event);

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, BUF_MAX);
} events SEC(".maps");

struct renamedata___x {
    struct user_namespace* old_mnt_userns;
    struct new_mnt_idmap* new_mnt_idmap;
} __attribute__((preserve_access_index));

static __always_inline struct event* event_init(
        u8 effect_type,
        u8 path_type,
        u64 timestamp)
{
    struct event* event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (! event) {
        elog("No event could be reserved");
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;  // A userspace "pid" is the kernel's "tgid"
    u32 tid = (u32)pid_tgid;   // And a "tid" is the kernel's "pid"
    event->timestamp = timestamp;
    event->buf_len = 0;
    event->event_group_id = (u16)timestamp;
    event->pid = pid;
    event->effect_type = effect_type;
    event->path_type = path_type;
    return event;
}

static __always_inline u8 path_type_from_mode(umode_t mode)
{
    switch (mode & S_IFMT) {
        case S_IFIFO : return PT_SYMLINK;
        case S_IFCHR : return PT_HARDLINK;
        case S_IFDIR : return PT_DIR;
        case S_IFBLK : return PT_BLOCK;
        case S_IFREG : return PT_FILE;
        case S_IFLNK : return PT_SYMLINK;
        case S_IFSOCK : return PT_SOCKET;
        default : return PT_UNKNOWN;
    }
}

/*  Sometimes, an inode's mode has not been determined yet.
    Can happen when:
      - Renaming a path, an "intermediate" renamed-to path is given a
        creation event, but has no mode until the final rename-to event.
      - Others... to investigate.
    The mode will be read as 0 in those cases and we'll return PT_UNKNOWN.
*/
static __always_inline u8
path_type_from_dentry(struct dentry* dentry)
{
    struct inode* inode;
    umode_t mode;
    if (read_ptr(&inode, &dentry->d_inode)) {
        wlog("Failed to read inode from dentry");
        return PT_UNKNOWN;
    }
    read_concrete(&mode, &inode->i_mode);
    return path_type_from_mode(mode);
}

static __always_inline u32 resolve_dents_to_events(
        struct dentry* head,
        u8 effect_type,
        u8 guess_path_type,
        u64 timestamp,
        u64 last_event_submit_flags)
{
    u8 depth = 0;
    u16 total_len = 0;
    u8 path_type;
    switch (guess_path_type) {
        case PT_UNKNOWN : path_type = path_type_from_dentry(head); break;
        default : path_type = guess_path_type; break;
    }
    struct event* event;

    dlog("@%lu et: %d pt: %d", timestamp, effect_type, path_type);

#pragma unroll
    for (; depth < SUBPATH_DEPTH_MAX; ++depth) {
        struct dentry* parent;
        struct qstr head_name;
        struct qstr parent_name;
        /*  This doesn't work for symbolic links.
              @ 351041545198698 link symlink pid:1137832
              > /home/edant/dev/watcher/out/this/Release/b
              > /
            For example.
        */
        if (read_ptr(&parent, &head->d_parent)) return 0;
        if (read_concrete(&head_name, &head->d_name)) return 0;
        if (read_concrete(&parent_name, &parent->d_name)) return 0;
        if (parent == head) {
            tlog("Reached root at depth %d with name %s",
                 depth,
                 head_name.name);
            break;
        }

        event = event_init(ET_CONT, PT_CONT, timestamp);
        if (! event) return 0;
        u32 len = head_name.len;
        len &= (NAME_MAX - 1);
        if (read_len(event->buf, len, head_name.name)) {
            elog("Failed to read dentry name into buf for user");
            bpf_ringbuf_discard(event, 0);
            return 0;
        }
        tlog("%s", event->buf);
        total_len += len;
        event->buf_len = len;
        bpf_ringbuf_submit(event, BPF_RB_NO_WAKEUP);

        if (total_len + parent_name.len > COMMON_PATH_MAX) {
            elog("Path too large, must truncate");
            break;
        }
        head = parent;
    }

    event = event_init(effect_type, path_type, timestamp);
    if (! event) return 0;
    bpf_ringbuf_submit(event, last_event_submit_flags);
    return depth;
}

/*  Probes for securty_path ops. */

/*  This probe recognizes special files (character devices, block devices, etc.)
    but it also recognizes regular files, it just doesn't report them as such.
    So, disabled for now. */

#if 0
SEC("kprobe/security_path_mknod")

int BPF_KPROBE(
        kprobe__security_path_mknod,
        struct path* dir,
        struct dentry* dentry,
        umode_t mode,
        unsigned int dev)
{
    tlog("security_path_mknod_enter");
    resolve_dents_to_events(dentry, ET_CREATE, NULL, bpf_ktime_get_ns(), BPF_RB_FORCE_WAKEUP);
    return 0;
}
#endif

SEC("kprobe/security_path_unlink")

int BPF_KPROBE(
        kprobe__security_path_unlink,
        struct path* dir,
        struct dentry* dentry)
{
    tlog("security_path_unlink_enter");
    resolve_dents_to_events(
            dentry,
            ET_DELETE,
            PT_UNKNOWN,
            bpf_ktime_get_ns(),
            BPF_RB_FORCE_WAKEUP);
    return 0;
}

SEC("kprobe/security_path_mkdir")

int BPF_KPROBE(
        kprobe__security_path_mkdir,
        struct path* dir,
        struct dentry* dentry,
        umode_t mode)
{
    tlog("security_path_mkdir_enter");
    resolve_dents_to_events(
            dentry,
            ET_CREATE,
            PT_DIR,
            bpf_ktime_get_ns(),
            BPF_RB_FORCE_WAKEUP);
    return 0;
}

SEC("kprobe/security_path_rmdir")

int BPF_KPROBE(
        kprobe__security_path_rmdir,
        struct path* dir,
        struct dentry* dentry)
{
    tlog("security_path_rmdir_enter");
    resolve_dents_to_events(
            dentry,
            ET_DELETE,
            PT_DIR,
            bpf_ktime_get_ns(),
            BPF_RB_FORCE_WAKEUP);
    return 0;
}

SEC("kprobe/security_path_rename")

int BPF_KPROBE(
        kprobe__security_path_rename,
        struct path* old_dir,
        struct dentry* old_dentry,
        struct path* new_dir,
        struct dentry* new_dentry)
{
    tlog("security_path_rename_enter");
    u64 timestamp = bpf_ktime_get_ns();
    resolve_dents_to_events(
            old_dentry,
            ET_ASSOC,
            PT_UNKNOWN,
            timestamp,
            BPF_RB_NO_WAKEUP);
    resolve_dents_to_events(
            new_dentry,
            ET_RENAME,
            PT_UNKNOWN,
            timestamp,
            BPF_RB_FORCE_WAKEUP);
    return 0;
}

SEC("kprobe/security_path_link")

int BPF_KPROBE(
        kprobe__security_path_link,
        struct dentry* old_dentry,
        struct path* new_dir,
        struct dentry* new_dentry)
{
    tlog("security_path_link_enter");
    u64 timestamp = bpf_ktime_get_ns();
    resolve_dents_to_events(
            old_dentry,
            ET_ASSOC,
            PT_UNKNOWN,
            timestamp,
            BPF_RB_NO_WAKEUP);
    resolve_dents_to_events(
            new_dentry,
            ET_LINK,
            PT_HARDLINK,
            timestamp,
            BPF_RB_FORCE_WAKEUP);
    return 0;
}

SEC("kprobe/security_path_symlink")

int BPF_KPROBE(
        kprobe__security_path_symlink,
        struct path* dir,
        struct dentry* dentry,
        char* old_name)
{
    tlog("security_path_symlink_enter");
    u64 timestamp = bpf_ktime_get_ns();
    resolve_dents_to_events(
            dentry,
            ET_ASSOC,
            PT_UNKNOWN,
            timestamp,
            BPF_RB_NO_WAKEUP);
    struct event* assoc = event_init(ET_LINK, PT_SYMLINK, timestamp);
    if (! assoc) return 0;
    u32 len = bpf_probe_read_str(assoc->buf, NAME_MAX, old_name);
    assoc->buf_len = len;
    bpf_ringbuf_submit(assoc, BPF_RB_FORCE_WAKEUP);
    return 0;
}

/*  Probes for securty_file ops. */

/*  This probe doesn't always see the right file mode, it seems to me.
    So, disabled for now. */

#if 0
SEC("kprobe/security_file_open")

int BPF_KPROBE(kprobe__security_file_open, struct file* file)
{
    unsigned flags;
    read_concrete(&flags, &file->f_flags);
    if (! (flags & FMODE_CREATED)) { return 0; }
    tlog("security_file_open_enter");
    u64 timestamp = bpf_ktime_get_ns();
    struct path path;
    read_concrete(&path, &file->f_path);
    struct dentry* dentry;
    read_ptr(&dentry, &path.dentry);
    static const enum path_type path_type = PT_FILE;
    resolve_dents_to_events(dentry, ET_CREATE, &path_type, timestamp, BPF_RB_FORCE_WAKEUP);
    return 0;
}
#endif

/*  Probes for securty_inode ops. */

SEC("kprobe/security_inode_create")

int BPF_KPROBE(
        kprobe__security_inode_create,
        struct inode* dir,
        struct dentry* dentry,
        umode_t mode)
{
    tlog("security_inode_create_enter");
    resolve_dents_to_events(
            dentry,
            ET_CREATE,
            path_type_from_mode(mode),
            bpf_ktime_get_ns(),
            BPF_RB_FORCE_WAKEUP);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
