#ifndef __EVENTPOLL_BUFFER_H__
#define __EVENTPOLL_BUFFER_H__

struct eventpoll_buffer {
    void *data;
    int refcnt;
    unsigned int used;
    unsigned int size;
    struct eventpoll_buffer *next;
};

static inline unsigned int
eventpoll_buffer_left(struct eventpoll_buffer *buffer)
{
    return buffer->size - buffer->used;
}

static inline unsigned int
eventpoll_buffer_pad(struct eventpoll_buffer *buffer, unsigned int alignment)
{
    return (alignment - (buffer->used & (alignment - 1))) & (alignment - 1);
}

#endif
