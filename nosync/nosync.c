void sync(void);
void syncfs(int fd);
int fsync(int fd);
int fdatasync(int fd);

void sync(void) {}
void syncfs(int fd) {}
int fsync(int fd) { return 0; }
int fdatasync(int fd) { return 0; }

