#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <pthread.h>
#include <sys/socket.h>
#include <time.h>



#define MAX_BUF 1024
#define MAX_DOMAINS 5

 
void convertName2RFC (unsigned char*,unsigned char*);
unsigned char* convertRFC2Name (unsigned char*,unsigned char*,int*);
void sendReply(unsigned short, unsigned char*, int, int, struct sockaddr_in);
 

void set_hora(int* hora);
void cria_pool(int num_workers);
void* func_thread_pool(void* id_thread);
int destroi_pool();
void gestao_config();
void *imprime_estatisticas();
void gestao_estatisticas();


//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
 
//Structure of a Query
struct QUERY
{
    unsigned char *name;
    struct QUESTION *ques;
};

// Estrutura da memória partilhada - Parâmetros de Configuração
typedef struct {
	int num_threads; 
	char domains[MAX_DOMAINS][MAX_BUF];
	char local_domain[MAX_BUF];
	char named_pipe_estat[MAX_BUF];
} mem_config;


// Estatísticas
typedef struct {
	int num_total_pedidos_processados;
	int num_pedidos_recusados;
	int num_enderecos_local;
	int num_enderecos_externo;
} estatistica;

// Estrutura dos pedidos
typedef struct pedido {
	int tipo_dominio; // 1: prioritario, 2: secundario 
	int socket;
	char buffer[1024];
	int query_id;
	struct sockaddr_in dest;
	struct pedido* next;
} request;

// Estrutura da pool de threads
typedef struct pool* threadpool;
typedef struct pool {
	int num_threads; //Número de threads na pool

	pthread_t* threads;
	int* ids;
	
	int num_requests_prio; //Número de pedidos na fila de espera de pedidos prioritaria
	request* head_prio;

	int num_requests; //Número de pedidos na fila de espera de pedidos secundaria
	request* head;

	pthread_mutex_t lock;
	pthread_cond_t not_empty;
	pthread_cond_t empty;

	// Flags utilizadas na destruição da pool de threads
	int flag_fechada;
	int flag_shutdown;

} poolthreads;

mem_config* configuracoes; //Memória partilhada das configurações
sem_t* mem; // Semáforo para controlar acesso à memória partilhada das configurações

void send_local(request* pedido);
int port, socket_conn, new_conn, size;
int shmid, shesta, mqid;
int hora_arranque[3], hora_actual[6]; 
pid_t processos[2]; 
threadpool pool_main; // Apenas irá ser criada uma pool de threads
estatistica msg;
char * src;

//Vai buscar a hora, os minutos e os segundos actuais
void set_hora(int* hora){
	struct tm* nova_hora;
	time_t hour;
	time(&hour);
	nova_hora = localtime(&hour);
	hora[0] = nova_hora->tm_hour;
	hora[1] = nova_hora->tm_min;
	hora[2] = nova_hora->tm_sec;
}

void set_hora_data(int* hora){
	struct tm* nova_hora;
	time_t hour;
	time(&hour);
	nova_hora = localtime(&hour);
	hora[0] = nova_hora->tm_hour;
	hora[1] = nova_hora->tm_min;
	hora[2] = nova_hora->tm_sec;
	hora[3] = nova_hora->tm_mday;
	hora[4] = nova_hora->tm_mon + 1;
	hora[5] = nova_hora->tm_year+1900;
}

void read_config_file(){
	char line[MAX_BUF];
	char temp_line[MAX_BUF], other_temp_line[MAX_BUF];
	int run_line, conta, what_we_want, run_temp;
	int num_threads, domain_counter;
	FILE *fp;
	fp = fopen("config.txt", "r");

	conta = 0;
	while(fgets(line, MAX_BUF, fp)!= NULL){
		conta ++;
		run_line = 0;
		while (line[run_line] != '='){
			run_line ++;
		}
		run_line++;

		if (line[run_line] == ' '){
			run_line++;
		}

		what_we_want = 0;
		while((line[run_line] != '\0') && (line[run_line] != '\n')){
			temp_line[what_we_want] = line[run_line];
			what_we_want++;
			run_line++;
		}
		temp_line[what_we_want] = '\0';

		switch(conta){
			case 1:
				num_threads = atoi(temp_line);
				configuracoes->num_threads = num_threads;
				//printf("\nNUM THREADS: %d\n", num_threads);
				break;
			
			case 2:
				run_line= 0;
				run_temp = 0;
				domain_counter = 0;
				while ((temp_line[run_line] != '\n') && (temp_line[run_line] != '\0')){
					if (temp_line[run_line] ==  ';'){
						other_temp_line[run_temp] = '\0';
						//puts(other_temp_line);
						strcpy(configuracoes->domains[domain_counter], other_temp_line);
						run_line++;
						bzero(other_temp_line, sizeof(other_temp_line));
						run_temp = 0;
						domain_counter++;
					}
					else if (temp_line[run_line] == ' ')
						run_line++;

					else{
						other_temp_line[run_temp] = temp_line[run_line];
						run_temp++;
						run_line++;
					}
				}
				other_temp_line[run_temp] = '\0';
				strcpy(configuracoes->domains[domain_counter], other_temp_line);
				//puts(other_temp_line);
				break;

			case 3:
				run_line= 0;
				run_temp = 0;
				while ((temp_line[run_line] != '\n') && (temp_line[run_line] != '\0')){
					if (temp_line[run_line] == ' ')
						run_line++;
					else{
						other_temp_line[run_temp] = temp_line[run_line];
						run_temp++;
						run_line++;
					}
				}
				other_temp_line[run_temp] = '\0';
				//Pôr o other_temp_line na estrutura -. LOCAL DOMAIN
				strcpy(configuracoes->local_domain, other_temp_line);
				//configuracoes->local_domain = other_temp_line;
				//puts(other_temp_line);
				break;

			case 4:
				run_line= 0;
				run_temp = 0;
				while ((temp_line[run_line] != '\n') && (temp_line[run_line] != '\0')){
					if (temp_line[run_line] == ' ')
						run_line++;
					else{
						other_temp_line[run_temp] = temp_line[run_line];
						run_temp++;
						run_line++;
					}
				}
				other_temp_line[run_temp] = '\0';
				//Pôr o other_temp_line na estrutura -. NAMED PIPE STATISTICS
				strcpy(configuracoes->named_pipe_estat, other_temp_line);
				//configuracoes->named_pipe_estat = other_temp_line;
				//puts(other_temp_line);
				break;

			default:
				printf("\nCHECK CONFIGURATION FILE!!\n");
		}
	}
	fclose(fp);
}


//Cria a pool de threads
void cria_pool(int num_workers){
	int i;
	// Se ocorrer um erro na alocação de memória, imprime uma mensagem de erro e sai
	if((pool_main = (threadpool) malloc(sizeof(poolthreads))) == NULL){
		printf("ERRO na alocação de memória\n");
		exit(-1);
	}

	// Inicialização
	pool_main->num_threads = num_workers;

	// Se ocorrer um erro na alocação de memória, imprime uma mensagem de erro e sai
	if((pool_main->threads = (pthread_t*) malloc(num_workers * sizeof(pthread_t))) == NULL){
		printf("ERRO na alocação de memória\n");
		exit(-1);
	}

	// Se ocorrer um erro na alocação de memória, imprime uma mensagem de erro e sai
	if((pool_main->ids = (int*) malloc(num_workers * sizeof(int))) == NULL){
		printf("ERRO na alocação de memória\n");
		exit(-1);
	}

	//Inicialização
	pool_main->num_requests_prio = 0;
	pool_main->head_prio = NULL;

	pool_main->num_requests = 0;
	pool_main->head = NULL;
	
	pool_main->flag_fechada = 0;
	pool_main->flag_shutdown = 0;

	pthread_mutex_init(&(pool_main->lock), NULL);
	pthread_cond_init(&(pool_main->not_empty), NULL);
	pthread_cond_init(&(pool_main->empty), NULL);

	// Criação das threads da pool
	for(i=0; i<num_workers; i++){
		pool_main->ids[i] = i;
		pthread_create(&(pool_main->threads[i]), NULL, func_thread_pool, &(pool_main->ids[i]));
	}
}


/* Função de cada uma das threads da pool
 * Verifica se existem pedidos na fila de espera
 * e responde de forma adequada conforme haja ou não pedidos disponíveis */
void* func_thread_pool(void* id_thread){
	request* novo_pedido;
	int id = *((int*) id_thread);

	while(1){
		pthread_mutex_lock(&(pool_main->lock));

		while(pool_main->num_requests_prio == 0 && pool_main->num_requests == 0 && (!pool_main->flag_shutdown)){ // Não existem pedidos na fila de espera e a pool não vai ser destruída
			pthread_cond_wait(&(pool_main->not_empty), &(pool_main->lock)); // Aguarda por pedidos
		}
		if(pool_main->flag_shutdown){ //A pool vai ser destruída
			pthread_mutex_unlock(&(pool_main->lock));
			pthread_exit(NULL); //Termina a thread
		}
		// Vai buscar o próximo pedido da fila de espera dos pedidos prioritarios 
		if (pool_main->num_requests_prio != 0){		
			novo_pedido = pool_main->head_prio;
		
			pool_main->num_requests_prio--;
			if(pool_main->num_requests_prio == 0){
				pool_main->head_prio = NULL;
			}
			else
				pool_main->head_prio = novo_pedido->next;
			if(pool_main->num_requests_prio == 0) //A fila de espera ficou sem pedidos
				pthread_cond_signal(&(pool_main->empty)); //Sinaliza a variável de condição empty
		}
		// Vai buscar o próximo pedido da fila de espera dos pedidos secundarios
		else{
			novo_pedido = pool_main->head;
		
			pool_main->num_requests--;
			if(pool_main->num_requests == 0){
				pool_main->head = NULL;
			}
			else
				pool_main->head = novo_pedido->next;
			if(pool_main->num_requests == 0) //A fila de espera ficou sem pedidos
				pthread_cond_signal(&(pool_main->empty)); //Sinaliza a variável de condição empty
		}

		pthread_mutex_unlock(&(pool_main->lock));
		

		// Atende o próximo pedido prioritário
		if(novo_pedido->tipo_dominio == 1)
			send_local(novo_pedido);
	
		// Atende o próximo pedido secundário
		//else if(novo_pedido->tipo_dominio == 2)

		free(novo_pedido);
		sleep(5);
	}

	pthread_exit(NULL);
}

// Adiciona novo pedido à fila de espera
int adiciona_pedido(int tipo_dominio, int socket, char* buffer, int query_id, struct sockaddr_in dest){
	request *novo_pedido, *aux;

	// Garante exclusão mútua - bloqueia o mutex
	pthread_mutex_lock(&(pool_main->lock));
	
	// A pool de threads vai ser destruída
	if(pool_main->flag_shutdown || pool_main->flag_fechada){
		pthread_mutex_unlock(&(pool_main->lock));
		return -1;
	}

	// Aloca memória para o novo pedido
	novo_pedido = (request*) malloc(sizeof(request));
	novo_pedido->tipo_dominio = tipo_dominio;
	novo_pedido->socket = socket;
	strcpy(novo_pedido->buffer, buffer);
	novo_pedido->query_id = query_id;
	novo_pedido->dest = dest;
	novo_pedido->next = NULL;

	//Adiciona pedido à fila de espera
	if (tipo_dominio == 1){
		if(pool_main->num_requests_prio == 0){
			pool_main->head_prio = novo_pedido;
		}
		else{
			aux = pool_main->head_prio;
			while(aux->next != NULL)
				aux = aux->next;
			aux->next = novo_pedido;
		}
		pool_main->num_requests_prio++;

	}
	else{
		if(pool_main->num_requests == 0){
			pool_main->head = novo_pedido;
		}
		else{
			aux = pool_main->head_prio;
			while(aux->next != NULL)
				aux = aux->next;
			aux->next = novo_pedido;
		}
		pool_main->num_requests++;
	}
	pthread_cond_broadcast(&(pool_main->not_empty)); // sinaliza todas as threads bloquadas na variável de condição not_empty -- a fila de espera prioritária já tem pedidos
	pthread_mutex_unlock(&(pool_main->lock)); // Desbloqueia o mutex
	return 0;
}


/* Destrói a pool antes de terminar --> a flag flag_shutdown é activada
 * e as threads da pool terminam a sua execução 
*/
int destroi_pool(){
	int i;
	request* aux;

	pthread_mutex_lock(&(pool_main->lock));

	pool_main->flag_fechada = 1;

	// Aguarda que os pedidos a ser atendidos de momento fiquem concluídos
	while(pool_main->num_requests != 0)
		pthread_cond_wait(&(pool_main->empty), &(pool_main->lock));

	pool_main->flag_shutdown = 1;
	pthread_mutex_unlock(&(pool_main->lock));

	// "Acorda" todas as threads para que possam verificar a flag flag_shutdown
	pthread_cond_broadcast(&(pool_main->not_empty));

	// Espera por todas as threads da pool
	for(i=0; i<pool_main->num_threads; i++)
		pthread_join(pool_main->threads[i], NULL);

	// Liberta os recursos
	free(pool_main->threads);
	free(pool_main->ids);
	while(pool_main->head_prio!=NULL){
		aux = pool_main->head_prio->next;
		pool_main->head_prio = pool_main->head_prio->next;
		free(aux);
	}
	while(pool_main->head!=NULL){
		aux = pool_main->head->next;
		pool_main->head = pool_main->head->next;
		free(aux);
	}
	free(pool_main);
	return 0;
} 


// Imprime as estatísticas 
void *imprime_estatisticas(){
	while(1){
		sleep(30);
		printf("\n\n********* ESTATÍSTICAS *********\n");
		printf("Hora arranque: %.2d:%.2d:%.2d\n", hora_arranque[0], hora_arranque[1], hora_arranque[2]); //Imprime a hora de arranque da execução
		printf("Número total de pedidos: %d\n", msg.num_total_pedidos_processados);
		printf("Número de pedidos recusados: %d\n", msg.num_pedidos_recusados);
		printf("Número de endereços do domínio local resolvidos: %d\n", msg.num_enderecos_local);
		printf("Número de endereços do domínios externos resolvidos: %d\n", msg.num_enderecos_externo);
		printf("Última informação: %d-%d-%d   %.2d:%.2d:%.2d\n", hora_actual[3], hora_actual[4], hora_actual[5], hora_actual[0], hora_actual[1], hora_actual[2]); //Imprime a hora actual/final
	}
}

// Processo Filho - Gestão de Estatísticas 
void gestao_estatisticas(){
	sleep(3);
	msg.num_pedidos_recusados = 0;
	msg.num_total_pedidos_processados = 0;
	msg.num_enderecos_local = 0;
	msg.num_enderecos_externo = 0;
	FILE* fich;
	int fd;
	char buf[MAX_BUF];
	pthread_t tid;
	pthread_create(&tid, NULL, &imprime_estatisticas, NULL);
	
	fd = open(configuracoes->named_pipe_estat, O_RDONLY);


	while(1){
		read(fd, buf, MAX_BUF);
		set_hora_data(hora_actual);

		if (strcmp(buf, "recusa") == 0){
			msg.num_pedidos_recusados++;
			msg.num_total_pedidos_processados++;
		}
		else if(strcmp(buf, "local") == 0){
			msg.num_enderecos_local++;
			msg.num_total_pedidos_processados++;	
		}
		else if (strcmp(buf, "externo") == 0){
			msg.num_enderecos_externo++;
			msg.num_total_pedidos_processados++;	
		}
		memset(&buf, 0, sizeof(buf));

	}
	close(fd);

	exit(0);
}
// Processo Filho - Gestão da configurações
void gestao_config(){
	printf("READING CONFIGURATION FILE...\n");
    read_config_file();

	exit(0);
}

// Vê o tamanho do ficheiro a ser mapeado para a memória
int get_stat(int fdin){
	struct stat pstatbuf;	
	if (fstat(fdin, &pstatbuf) < 0){	/* need size of input file */
		fprintf(stderr,"fstat error\n");
		exit(1);
	}
	return pstatbuf.st_size;
}

// Enviar a resposta quando se trata de um pedido local
void send_local(request* pedido){
	printf("ENVIAR RESPOSTA LOCAL\n");
	char localdomains[MAX_BUF], local_ip[MAX_BUF];
	int i,k,j;

	for(i = 0; i < strlen(src); i++){
		k = 0;
		while(src[i] != ' '){
			localdomains[k] = src[i];
			i++;
			k++;
		}
		localdomains[k] = '\0';
		if (strcmp(localdomains, pedido->buffer) == 0){
			j = 0;
			while ((src[i] != '\n')){
				if (src[i] != ' '){
					local_ip[j] = src[i];
					j++;
				}
				i++;
			}
			sendReply(pedido->query_id, pedido->buffer, inet_addr(local_ip), pedido->socket, pedido->dest); //Envia a resposta caso pertença ao localdns.txt!
			break;
		}
		else{
			while (src[i] != '\n')
				i++;
		} 
	}
}



int main( int argc , char *argv[]){

	set_hora(hora_arranque); // Determina a hora de arranque do Servidor
	struct sockaddr_in client_name;
	socklen_t client_name_len = sizeof(client_name);
	int i, fd, fdin, j, k;
	char *ptr;
	char req_buf[1024];
	char buffer[MAX_BUF], line[MAX_BUF];


	// Verifica o número de argumentos
	if(argc!=2) {
		printf("Usage: %s <port>\n", argv[0]);
		exit(1);
	}
	port = atoi(argv[1]);

	configuracoes = malloc(sizeof(mem_config));

	// Cria e mapeia a região de memória partilhada das configurações
	shmid = shmget(IPC_PRIVATE, sizeof(mem_config), IPC_CREAT|0700);
	if(shmid==-1){ 
		perror("ERRO ao criar memória partilhada");
		exit(1);
	}
    configuracoes = (mem_config*) shmat(shmid, NULL, 0); 
    if(configuracoes == (mem_config*) -1){
    	perror("ERRO no shmat");
    	exit(1);
    }
    // Inicializa e abre o semáforo que controla o acesso à memória partilhada das configurações
	sem_unlink("MEM");
	mem = sem_open("MEM", O_CREAT|O_EXCL, 0700, 1);
	if(mem==SEM_FAILED){
		perror("ERRO na criação do semáforo");
		exit(1);
	}

	//Mapeiar o ficheiro localdns.txt para memória (Memory mapped files)
	if ( (fdin = open("localdns.txt", O_RDONLY)) < 0)
	{
		fprintf(stderr,"Can't open localdns.txt for reading");
		exit(1);
	}
	size = get_stat(fdin);

	if ( (src = mmap(0, size, PROT_READ, MAP_FILE | MAP_PRIVATE, fdin, 0)) == (caddr_t) -1)
	{
		fprintf(stderr,"mmap error for input\n");
		exit(1);
	}
	
	// Cria os processos filho
	for(i=0; i<2; i++){
		if((processos[i] = fork()) == 0){
			switch(i){
				case 0:
					gestao_config();
					exit(0);
					break;
				case 1:
					gestao_estatisticas();
					exit(0);
					break;
			}
		}
	}
	sleep(3);
	cria_pool(configuracoes->num_threads);
	
	// Criar um named pipe
    mkfifo(configuracoes->named_pipe_estat, 0666);
    fd = open(configuracoes->named_pipe_estat, O_WRONLY);


	//*******************************
	//CODIGO DADO COMECA AQUI!!!!!
	//*******************************
	unsigned char buf[65536], *reader;
	int sockfd, stop;
	struct DNS_HEADER *dns = NULL;
	
	struct sockaddr_in servaddr,dest;
	socklen_t len;
	
	// Check arguments
	if(argc <= 1) {
		printf("Usage: dnsserver <port>\n");
		exit(1);
	}
	
	// Get server UDP port number
	int port = atoi(argv[1]);
	
	if(port <= 0) {
		printf("Usage: dnsserver <port>\n");
		exit(1);
	}
	
	
	// ****************************************
	// Create socket & bind
	// ****************************************
	
	// Create UDP socket
    sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
 
	if (sockfd < 0) {
         printf("ERROR opening socket.\n");
		 exit(1);
	}

	// Prepare UDP to bind port
	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	servaddr.sin_port=htons(port);
	
	// Bind application to UDP port
	int res = bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
	
	if(res < 0) {
         printf("Error binding to port %d.\n", servaddr.sin_port);
		 
		 if(servaddr.sin_port <= 1024) {
			 printf("To use ports below 1024 you may need additional permitions. Try to use a port higher than 1024.\n");
		 } else {
			 printf("Please make sure this UDP port is not being used.\n");
		 }
		 exit(1);
	}
	
	// ****************************************
	// Receive questions
	// ****************************************
	
	while(1) {
		// Receive questions
		len = sizeof(dest);
		printf("\n\n-- Waiting for DNS message --\n\n");
		if(recvfrom (sockfd,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , &len) < 0) {
			printf("Error while waiting for DNS message. Exiting...\n");
			exit(1);
		}
		
		printf("DNS message received\n");
		
		// Process received message
		dns = (struct DNS_HEADER*) buf;
		//qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
		reader = &buf[sizeof(struct DNS_HEADER)];
	 
		printf("\nThe query %d contains: ", ntohs(dns->id));
		printf("\n %d Questions.",ntohs(dns->q_count));
		printf("\n %d Answers.",ntohs(dns->ans_count));
		printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
		printf("\n %d Additional records.\n\n",ntohs(dns->add_count));
		
		// We only need to process the questions
		// We only process DNS messages with one question
		// Get the query fields according to the RFC specification
		struct QUERY query;
		if(ntohs(dns->q_count) == 1) {
			// Get NAME
			query.name = convertRFC2Name(reader,buf,&stop);
			reader = reader + stop;
			
			// Get QUESTION structure
			query.ques = (struct QUESTION*)(reader);
			reader = reader + sizeof(struct QUESTION);
			
			// Check question type. We only need to process A records.
			if(ntohs(query.ques->qtype) == 1) {
				printf("A record request.\n\n");
			} else {
				printf("NOT A record request!! Ignoring DNS message!\n");
				continue;
			}
			
		} else {
			printf("\n\nDNS message must contain one question!! Ignoring DNS message!\n\n");
			continue;
		}
		
		// Received DNS message fulfills all requirements.
		
		
		// ****************************************
		// Print received DNS message QUERY
		// ****************************************
		printf(">> QUERY: %s\n", query.name);
		printf(">> Type (A): %d\n", ntohs(query.ques->qtype));
		printf(">> Class (IN): %d\n\n", ntohs(query.ques->qclass));

		//VERIFICAR SE É PARA RECUSAR PEDIDO OU NÃO

		if (strstr(query.name, configuracoes->local_domain) != NULL){
			sprintf(buffer,"local");
	 		write(fd, buffer, sizeof(buffer));
	 		adiciona_pedido(1, sockfd, query.name, dns->id, dest);
			//adiciona pedido fila prioritaria
		}
		else{
			sprintf(buffer,"externo");
	 		write(fd, buffer, sizeof(buffer));
	 		adiciona_pedido(2, sockfd, query.name, dns->id, dest);
			//adiciona pedido a fila secundaria
		}

		// ****************************************
		// Example reply to the received QUERY
		// (Currently replying 10.0.0.2 to all QUERY names)
		// ****************************************
		//sendReply(dns->id, query.name, inet_addr("10.0.0.2"), sockfd, dest); //Caso não pertença ao localdns.txt....
		
	}
	
	//fechar o pipe
	close(fd);
	munmap(src,size);
	close(fdin);
    /* remove the FIFO */
    unlink(configuracoes->named_pipe_estat);
    destroi_pool();

    return 0;
}
 
/**
	sendReply: this method sends a DNS query reply to the client
	* id: DNS message id (required in the reply)
	* query: the requested query name (required in the reply)
	* ip_addr: the DNS lookup reply (the actual value to reply to the request)
	* sockfd: the socket to use for the reply
	* dest: the UDP package structure with the information of the DNS query requestor (includes it's IP and port to send the reply)
**/
void sendReply(unsigned short id, unsigned char* query, int ip_addr, int sockfd, struct sockaddr_in dest) {
		unsigned char bufReply[65536], *rname;
		char *rip;
		struct R_DATA *rinfo = NULL;
		
		//Set the DNS structure to reply (according to the RFC)
		struct DNS_HEADER *rdns = NULL;
		rdns = (struct DNS_HEADER *)&bufReply;
		rdns->id = id;
		rdns->qr = 1;
		rdns->opcode = 0;
		rdns->aa = 1;
		rdns->tc = 0;
		rdns->rd = 0;
		rdns->ra = 0;
		rdns->z = 0;
		rdns->ad = 0;
		rdns->cd = 0;
		rdns->rcode = 0;
		rdns->q_count = 0;
		rdns->ans_count = htons(1);
		rdns->auth_count = 0;
		rdns->add_count = 0;
		
		// Add the QUERY name (the same as the query received)
		rname = (unsigned char*)&bufReply[sizeof(struct DNS_HEADER)];
		convertName2RFC(rname , query);
		
		// Add the reply structure (according to the RFC)
		rinfo = (struct R_DATA*)&bufReply[sizeof(struct DNS_HEADER) + (strlen((const char*)rname)+1)];
		rinfo->type = htons(1);
		rinfo->_class = htons(1);
		rinfo->ttl = htonl(3600);
		rinfo->data_len = htons(sizeof(ip_addr)); // Size of the reply IP address

		// Add the reply IP address for the query name 
		rip = (char *)&bufReply[sizeof(struct DNS_HEADER) + (strlen((const char*)rname)+1) + sizeof(struct R_DATA)];
		memcpy(rip, (struct in_addr *) &ip_addr, sizeof(ip_addr));
		
		// Send DNS reply
		printf("\nSending Answer... ");
		if( sendto(sockfd, (char*)bufReply, sizeof(struct DNS_HEADER) + (strlen((const char*)rname) + 1) + sizeof(struct R_DATA) + sizeof(ip_addr),0,(struct sockaddr*)&dest,sizeof(dest)) < 0) {
			printf("FAILED!!\n");
		} else {
			printf("SENT!!!\n");
		}
}

/**
	convertRFC2Name: converts DNS RFC name to name
**/
u_char* convertRFC2Name(unsigned char* reader,unsigned char* buffer,int* count) {
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    while(*reader!=0) {
        if(*reader>=192) {
            offset = (*reader)*256 + *(reader+1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1;
        } else {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0) {
            *count = *count + 1;
        }
    }
 
    name[p]='\0';
    if(jumped==1) {
        *count = *count + 1;
    }
 
    for(i=0;i<(int)strlen((const char*)name);i++) {
        p=name[i];
        for(j=0;j<(int)p;j++) {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0';
    return name;
}

/**
	convertName2RFC: converts name to DNS RFC name
**/
void convertName2RFC(unsigned char* dns,unsigned char* host) {
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) {
        if(host[i]=='.') {
            *dns++ = i-lock;
            for(;lock<i;lock++) {
                *dns++=host[lock];
            }
            lock++;
        }
    }
    *dns++='\0';
}