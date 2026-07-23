// Заглушки для zlib, чтобы линкер отвязался от библиотеки
int deflateInit_(void* strm, int level, const char* version, int stream_size) { return -1; }
int deflate(void* strm, int flush) { return -1; }
int deflateEnd(void* strm) { return -1; }
int inflateInit_(void* strm, const char* version, int stream_size) { return -1; }
int inflate(void* strm, int flush) { return -1; }
int inflateEnd(void* strm) { return -1; }