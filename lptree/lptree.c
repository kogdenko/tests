#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct node {
	union {
		struct {
			uint32_t key;
			uint8_t len;
			uint16_t data;
			uint16_t parent_id;
			uint16_t children_id[2];
		};
		LIST_ENTRY(node) list;
	};
};

LIST_HEAD(node_head, node);

struct lptree32 {
	struct node *nodes;
	struct node *root;
	int nr_nodes;
	struct node_head free_head;
};

static int node_add(struct lptree32 *tree, struct node *node,
                    uint32_t key, int len, int cmp,
                    uint16_t data);

static int
get_node_id(struct lptree32 *tree, struct node *node)
{
	return node - tree->nodes;
}

static struct node *
get_node(struct lptree32 *tree, uint16_t node_id)
{
	if (node_id == 0) {
		return NULL;
	} else {
		return tree->nodes + node_id;
	}
}

static struct node *
new_node(struct lptree32 *tree)
{
	struct node *node;
	assert(!LIST_EMPTY(&tree->free_head));	
	node = LIST_FIRST(&tree->free_head);
	LIST_REMOVE(node, list);
	memset(node, 0, sizeof(*node));
	tree->nr_nodes++;
	return node;
}

static void
free_node(struct lptree32 *tree, struct node *node)
{
	LIST_INSERT_HEAD(&tree->free_head, node, list);
	tree->nr_nodes--;
}

static struct node *
get_child(struct lptree32 *tree, struct node *node, int idx)
{
	int child_id;
	struct node *child;
	child_id = node->children_id[idx];
	if (child_id == 0) {
		return NULL;
	} else {
		child = tree->nodes + child_id;
		assert(tree->nodes + child->parent_id == node);
		return child;
	}
}

static void
set_key(struct node *node, uint32_t key, int len)
{
	uint32_t mask;
	mask = 0xffffffff;
	mask <<= (32 - len);
	node->key = key & mask;
	node->len = len;
}

static void
add_child(struct lptree32 *tree, struct node *node, int idx,
          uint32_t key, int len, uint16_t data)
{
	struct node *child;
	assert(idx < 2);
	assert(node->children_id[idx] == 0);
	child = new_node(tree);
	child->parent_id = get_node_id(tree, node);
	set_key(child, key, len);
	child->data = data;
	node->children_id[idx] = get_node_id(tree, child);
}

static int
node_cmp(struct node *node, uint32_t key, int len)
{
	int rc;
	if (len > node->len) {
		len = node->len;
	}
	rc = fls(key  ^ node->key);
	if (rc == 0) {
		rc = len;
	} else {
		assert(rc > 0 && rc <= 32);
		rc = 32 - rc;
		if (rc > len) {
			rc = len;
		}
	}
	assert(rc >= 0 && rc <= len);
//	printf("CMP: %x^%x=%x rc=%d, %d\n",
//		key, node->key, key ^ node->key, rc, len);
	return rc;
}

static int
node_search(struct lptree32 *tree, struct node *node, uint32_t key)
{
	int i, rc;
	struct node *child;
	rc = node_cmp(node, key, 32);
	if (rc < node->len) {
		return -ESRCH;
	}
	key <<= node->len;
	for (i = 0; i < 2; ++i) {
		child = get_node(tree, node->children_id[i]);
		if (child) {
			rc = node_search(tree, child, key);
			if (rc > 0) {
				return rc;
			}
		}
	}
	return node->data;
}

static void
node_del(struct lptree32 *tree, struct node *node)
{
	int i, tmp, child_id, nr_children;
	struct node *x, *parent, *child;
	nr_children = 0;
	if (node->len == 0) {
		// Root
		node->data = 0;
		return;
	}
	child = NULL;
	for (i = 0; i < 2; ++i) {
		x = get_node(tree, node->children_id[i]);
		if (x != NULL) {
			child = x;
			nr_children++;
		}
	}
	node->data = 0;
	if (nr_children == 2) {
		return;
	}
	parent = get_node(tree, node->parent_id);
	assert(parent);
	if (nr_children == 0) {
		child_id = 0;
	} else {
		child_id = get_node_id(tree, child);
		// Merge into child
		assert(nr_children == 1);
		assert(child != NULL);
		child->key >>= node->len;
		child->key  |= node->key;
		child->len  += node->len;
		child->parent_id = node->parent_id;
	}
	for (i = 0; i < 2; ++i) {	
		tmp = parent->children_id[i];
		if (get_node(tree, tmp) == node) {
			parent->children_id[i] = child_id;
			break;
		}
	}
	free_node(tree, node);
	if (parent->data == 0) {
		node_del(tree, parent);
	}
}

static struct node *
node_find(struct lptree32 *tree, struct node *node, uint32_t key, int len)
{
	int i, rc;
	struct node *x, *child;
	if (node->len > len) {
		return NULL;
	}
	rc = node_cmp(node, key, len);
	if (rc < node->len) {
		return NULL;
	}
	if (node->len == len) {
		return node;
	}
	key <<= node->len;
	len  -= node->len;
	for (i = 0; i < 2; ++i) {
		child = get_node(tree, node->children_id[i]);
		if (child != NULL) {
			x = node_find(tree, child, key, len);
			if (x != NULL) {
				return x;
			}
		}
	}
	return NULL;
}

static int
node_addA(struct lptree32 *tree, struct node *node,
          uint32_t key, int len,
          uint16_t data)
{
	int i, rc, ccmp, empty;
	struct node *child;
	empty = -1;
	for (i = 0; i < 2; ++i) {
		child = get_child(tree, node, i);
		if (child == NULL) {
			empty = i;
		} else {
			ccmp = node_cmp(child, key, len);
			if (ccmp) {
				rc = node_add(tree, child, key, len, ccmp, data);
				return rc;
			}
		}
	}
	assert(empty != -1);
	add_child(tree, node, empty, key, len, data);
	return data;
}

static int
node_add(struct lptree32 *tree, struct node *node,
          uint32_t key, int len, int cmp,
          uint16_t data)
{
	int i, rc;
	uint16_t x_id;
	struct node *x, *y, *child, *parent;
	assert(len > 0);
	assert(cmp <= node->len);
	assert(cmp <= len);
	assert(cmp > 0 || (cmp == 0 && node->len == 0));
	if (cmp == node->len) {
		if (len > node->len) {
			key <<= cmp;
			len  -= cmp;
			rc = node_addA(tree, node, key, len, data);
			return rc;
		} else if (len == node->len) {
			if (node->data == 0) {
				node->data = data;
			}
			return node->data;
		}
	}
	x = new_node(tree);
	x_id = get_node_id(tree, x);
	set_key(x, node->key, cmp);
	x->parent_id = node->parent_id;
	x->children_id[0] = get_node_id(tree, node);
	assert(node->parent_id != 0);
	parent = get_node(tree, node->parent_id);
	for (i = 0; i < 2; ++i) {
		child = get_node(tree, parent->children_id[i]);
		if (child == node) {
			parent->children_id[i] = x_id;
			break;
		}
	}
	assert(i < 2);
	node->key <<= cmp;
	node->len  -= cmp;
	node->parent_id = x_id;
	if (len == cmp) {
		x->data = data;
		return data;
	}
	y = new_node(tree);
	set_key(y, key << cmp, len - cmp);
	y->parent_id = x_id;
	y->data = data;
	x->children_id[1] = get_node_id(tree, y);
	return data;
}

static const char *
ktoa(uint32_t key, int len)
{
	int i, bit;
	static char buf[33];
	assert(len <= 32);
	for (i = 0; i < len; ++i) {
		bit = key & (1 << (31 - i));
		buf[i] = bit ? '1' : '0';
	}
	buf[len] = '\0';
	return buf;
}

static void
lptree32_node_print(struct lptree32 *tree, struct node *node, int spaces)
{
	int i;
	uint16_t child_id;
	struct node *child;
	printf("%*s%s%s\n",
		spaces, "", ktoa(node->key, node->len),
		node->data ? "*" : "");
	for (i = 0; i < 2; ++i) {
		child_id = node->children_id[i];
		if (child_id) {
			child = get_node(tree, child_id);
			lptree32_node_print(tree, child, spaces + node->len);
		}
	}
}

static void
lptree32_print(struct lptree32 *tree)
{
	lptree32_node_print(tree, tree->root, 0);
}

static int
lptree32_init(struct lptree32 *tree, int n)
{
	int i;
	struct node *node;
	assert(n > 32);
	tree->nodes = malloc(n * sizeof(node));
	tree->nr_nodes = 0;
	assert(tree->nodes != NULL);
	tree->root = tree->nodes + 1;
	memset(tree->root, 0, sizeof(*tree->root));
	LIST_INIT(&tree->free_head);
	for (i = 2; i < n; ++i) {
		node = tree->nodes + i;
		LIST_INSERT_HEAD(&tree->free_head, node, list);
	}
	return 0;
}

static int
lptree32_search(struct lptree32 *tree, uint32_t key)
{
	int rc;
	rc = node_search(tree, tree->root, key);
	return rc;
}

static int
lptree32_del(struct lptree32 *tree, uint32_t key, int len)
{
	struct node *node;
	node = node_find(tree, tree->root, key, len);
	if (node == NULL) {
		return -ESRCH;
	}
	node_del(tree, node);
	return 0;
}

static int
lptree32_add(struct lptree32 *tree, uint32_t key, int len, uint16_t data)
{
	int rc;
	assert(data != 0);
	rc = node_add(tree, tree->root, key, len, 0, data);
	return rc;
}

static int
parse_net(char *s, struct in_addr *in)
{
	int rc, len;
	char *p, *endptr;
	p = strchr(s, '/');
	if (p == NULL) {
		len = 32;
	} else {
		len = strtoul(p + 1, &endptr, 10);
		*p = '\0';
	}
	rc = inet_aton(s, in);
	if (p != NULL) {
		*p = '/';
	}
	if (rc != 1) {
		return -1;
	}
	if (*endptr != '\0' && strchr("\r\n\t ", *endptr) == NULL) {
		return -1;
	}
	if (len > 32) {
		return -1;
	}
	return len;
}

static void
read_file(struct lptree32 *tree, const char *filename, int action)
{
	char buf[256];
	char *s;
	int rc, line;
	struct in_addr in;
	FILE *file;
	file = fopen(filename, "r");
	if (file == NULL) {
		fprintf(stderr, "fopen('%s') failed (%s)\n",
			filename, strerror(errno));
		return;
	}
	line = 0;
	while ((s = fgets(buf, sizeof(buf), file)) != NULL) {
		line++;
		rc = parse_net(s, &in);
		if (rc == -1) {
			fprintf(stderr, "error at '%s':%d\n", filename, line);
			continue;
		}
		if (action) {
			rc = lptree32_add(tree, ntohl(in.s_addr), rc, line);
			if (rc != line) {
				fprintf(stderr, "add return %d at '%s':%d\n",
					rc, filename, line);
			}
		} else {
			rc = lptree32_del(tree, ntohl(in.s_addr), rc);
			if (rc < 0) {
				fprintf(stderr, "del failed at '%s':%d\n",
					filename, line);
			}
		}
	}
	fclose(file);
}

static void
search_file(struct lptree32 *tree, const char *filename)
{
	char buf[256];
	char *s;
	int i, rc, line, nr_keys, found;
	struct in_addr in;
	struct timeval tv0, tv1;
	FILE *file;
	uint32_t *keys;
	file = fopen(filename, "r");
	if (file == NULL) {
		fprintf(stderr, "fopen('%s') failed (%s)\n",
			filename, strerror(errno));
		return;
	}
	found = 0;
	nr_keys = 0;
	keys = malloc(10000 * sizeof(uint32_t));
	line = 0;
	while ((s = fgets(buf, sizeof(buf), file)) != NULL) {
		line++;
		rc = parse_net(s, &in);
		if (rc == -1) {
			fprintf(stderr, "error at '%s':%d\n", filename, line);
			continue;
		}
		if (nr_keys == 10000) {
			break;
		}
		keys[nr_keys++] = ntohl(in.s_addr);
	}
	fclose(file);
	gettimeofday(&tv0, NULL);
	for (i = 0; i < nr_keys; ++i) {
		if (lptree32_search(tree, keys[i]) > 0) {
			found++;
		}
	}
	gettimeofday(&tv1, NULL);
	free(keys);
	printf("found=%d(%d), dt=%luus\n", found, nr_keys,
		1000000 * (tv1.tv_sec - tv0.tv_sec) + tv1.tv_usec - tv0.tv_usec);
}

static void
invalid_arg(int opt, char *arg)
{
	printf("Invalid argument '-%c': '%s'\n", opt, arg);
	exit(1);
}

int
main(int argc, char **argv)
{
	int rc, len, opt, idx;
	struct in_addr in;
	struct lptree32 tree;

	//int x, y, z;
	//x = strtoul(argv[1], NULL, 10);
	//y = strtoul(argv[2], NULL, 10);
	//z = x ^ y;
	//printf("%x^%x=%x\n", x, y, z);
	//return 0;
	//printf("%d\n", fls(strtoul(argv[1], NULL, 10)));
	//return 0;

	idx = 1;
	lptree32_init(&tree, 2 * 16384);
	printf("sizeof(node)=%lu\n", sizeof(struct node));
//	assert(0);

	while ((opt = getopt(argc, argv, "a:A:d:D:s:S:p")) != -1) {
		switch (opt) {
		case 'a':
			len = parse_net(optarg, &in);
			if (len == -1) {
				invalid_arg(opt, optarg);
			}
			rc = lptree32_add(&tree, ntohl(in.s_addr), len, idx);
			idx++;
			printf("Add: %s/%d (%d)\n", inet_ntoa(in), len, rc);
			break;
		case 'A':
			read_file(&tree, optarg, 1);
			break;
		case 'd':
			len = parse_net(optarg, &in);
			if (len == -1) {
				invalid_arg(opt, optarg);
			}
			rc = lptree32_del(&tree, ntohl(in.s_addr), len);
			printf("Remove: %s/%d (%d)\n", inet_ntoa(in), len, rc);
			break;
		case 'D':
			read_file(&tree, optarg, 0);
			break;
		case 's':
			rc = inet_aton(optarg, &in);
			if (rc != 1) {
				invalid_arg(opt, optarg);
			}
			rc = lptree32_search(&tree, ntohl(in.s_addr));
			printf("Search: %d\n", rc);
			break;
		case 'S':
			search_file(&tree, optarg);
			break;
		case 'p':
			lptree32_print(&tree);
			break;
		}
	}

	printf("Number of nodes: %d\n", tree.nr_nodes);

	return 0;
}
