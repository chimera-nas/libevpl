#ifndef __EVENTPOLL_CLIENT_H__
#define __EVENTPOLL_CLIENT_H__

struct eventpoll;

struct eventpoll * eventpoll_init();

void eventpoll_destroy(struct eventpoll *eventpoll);

#endif
