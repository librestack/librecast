typedef struct node_t {
        char *name;
        char *ip;
        time_t seen;
        int stratum;
        char *bridge;
        struct node_t *next;
} node_t;

int initialize();
void cleanup();
node_t *get_node(char *node);
void display_header(int rows, int cols);
void display_nodes();
void display_time();
void update();
void update_node(char *name, char *ip, int stratum, char *bridge);
int main();
