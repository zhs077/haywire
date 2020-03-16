#ifndef __EFC_LIST_H__H
#define __EFC_LIST_H__H

typedef struct __list_node list_link;
typedef struct __list_node list_head;


struct __list_node {
	struct __list_node *prev, *next;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

static inline void INIT_LIST_HEAD(list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(
	struct __list_node *neo,
	struct __list_node *prev,
	struct __list_node *next)
{
	neo->next = next;
	neo->prev = prev;
	__asm__ __volatile__("": : :"memory");
	prev->next = neo;
	next->prev = neo;
}

static inline void list_add(struct __list_node *neo,struct __list_node *head)
{
	__list_add( neo, head, head->next );
}

static inline void list_add_tail(
	struct __list_node *neo,
	struct __list_node * head)
{
	__list_add( neo, head->prev, head );
}

static inline void  __list_del(
	struct __list_node *prev,
	struct __list_node *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void  list_del(struct __list_node *entry)
{
	__list_del(entry->prev, entry->next);
	entry->prev=(struct __list_node *)0;
	entry->next=(struct __list_node *)0;
}

static inline int list_empty(const struct __list_node *head)
{
	return head->next == head;
}

static inline void list_switch(struct __list_node *head1, struct __list_node *head2)
{
	struct __list_node head;
	list_add(&head, head1);
	list_del(head1);
	list_add(head1, head2);
	list_del(head2);
	list_add(head2, &head);
	list_del(&head);
}

#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); \
        	pos = pos->next)

#define list_for_each_rev(pos, head) \
	for (pos = (head)->prev; pos != (head); \
		pos = pos->prev)

#define list_for_each_safe(pos, save, head) \
	for (pos = (head)->next, save = pos->next; pos != (head); \
		pos = save, save = pos->next)

#define list_for_each_rev_safe(pos, save, head) \
	for (pos = (head)->prev, save = pos->prev; pos != (head); \
		pos = save, save = pos->prev)

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({			\
		const typeof( ((type *)0)->member ) *__mptr = (const typeof( ((type *)0)->member ) *)(ptr); \
		(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define list_for_each2(pos, head) \
	for (; pos != (head); \
        	pos = pos->next)

#endif /*__EFC_LIST_H__H*/

