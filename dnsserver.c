/********************************************************************************
*						Sistemas Operativos 2015/2016							*
*								Servidor DNS 									*
*																				*
*				Rita Maria Faria de Almeida			2012169259					*
*			Tomás Morgado de Carvalho Conceição		2012138578					*
*																				*
* Tempo total: ~50h 																*
*********************************************************************************/


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
#include <sys/wait.h>
#include <sys/types.h>
#include <stdbool.h>


//processos - ps aux | grep server
//kill -SIGUSR1 num_processo


#define MAX_BUF 1024
#define MAX_DOMAINS 5

//DEBUG - Comentar para desactivar o DEBUG
//#define DEBUG
//DEBUG - Tirar o comentário para activar o DEBUG

 
void convertName2RFC (unsigned char*,unsigned char*);
unsigned char* convertRFC2Name (unsigned char*,unsigned char*,int*);
void sendReply(unsigned short, unsigned char*, int, int, struct sockaddr_in, int);


void* func_thread_pool(void* id_thread);
int destroi_pool();
int get_stat(int fdin);

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
	int num_domain_extern;
	bool manutencao;
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
	int socket; // 
	char buffer[MAX_BUF]; // String com o pedido
	int query_id; // ID da query
	struct sockaddr_in dest;
	struct pedido* next; // Ponteiro para o próximo pedido
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
sem_t* mmf; // Semáforo para controlar acesso ao memory mapped file


int port, sockfd, size, fd, fdin, fd_estatisticas_read, config_pid;
int shmid;
int hora_arranque[3], hora_actual[6]; 
pid_t processos[2]; 


threadpool pool_main; // Apenas irá ser criada uma pool de threads

estatistica msg;

char * local_domain_mmf; //Mapeia o ficheiro para memoria

void send_extern(request* pedido);
void send_local(request* pedido);

pthread_t thread_estatisticas;


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
	#ifdef DEBUG
	printf("DEBUG: A definir hora e data\n");
	#endif

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

//Lê o fichiro config.txt 
void read_config_file(){
	char line[MAX_BUF];
	char temp_line[MAX_BUF], other_temp_line[MAX_BUF];
	int run_line, conta, what_we_want, run_temp;
	int num_threads, domain_counter;
	FILE *fp;
	fp = fopen("config.txt", "r");

	#ifdef DEBUG
	printf("DEBUG: A ler ficheiro de configuracoes: config.txt...\n");
	#endif

	conta = 0;
	configuracoes->manutencao = false;
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
				#ifdef DEBUG
				printf("DEBUG: Numero de threads: %d\n", num_threads);
				#endif
				break;
			
			case 2:
				run_line= 0;
				run_temp = 0;
				domain_counter = 0;
				while ((temp_line[run_line] != '\n') && (temp_line[run_line] != '\0')){
					
					if (temp_line[run_line] ==  ';'){
						other_temp_line[run_temp] = '\0';
						strcpy(configuracoes->domains[domain_counter], other_temp_line);
						#ifdef DEBUG
						printf("DEBUG: Dominio lido: ");
						puts(other_temp_line);
						#endif
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
				#ifdef DEBUG
				printf("DEBUG: Dominio lido: ");
				puts(other_temp_line);
				#endif
				domain_counter++;
				configuracoes->num_domain_extern = domain_counter;
				#ifdef DEBUG
				printf("DEBUG: Numero de dominios lidos: %d\n", domain_counter);
				#endif
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
				strcpy(configuracoes->local_domain, other_temp_line);
				#ifdef DEBUG
				printf("DEBUG: Dominio local lido: ");
				puts(other_temp_line);
				#endif
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
				strcpy(configuracoes->named_pipe_estat, other_temp_line);
				#ifdef DEBUG
				printf("DEBUG: Named pipe estatistics: ");
				puts(other_temp_line);
				#endif
				break;

			default:
				printf("\nCHECK CONFIGURATION FILE!!\n");
		}
	}
	fclose(fp);
}

// Resposta ao sinal SIGINT --> Thread das estatisticas
void ctrl_c_esta(int sig){
	#ifdef DEBUG
	printf("DEBUG: Funcao ctrl_c chamada\n");
	#endif
	signal(SIGINT, ctrl_c_esta);
	if (pthread_cancel(thread_estatisticas) == 0)
		#ifdef DEBUG
		printf("DEBUG: Thread estatisticas destruída...\n");
		#endif
	exit(0);
}

// Resposta ao sinal SIGINT --> Libertação de recursos e limpeza ao terminar a aplicação
void ctrl_c(int sig){
	#ifdef DEBUG
	printf("\nDEBUG: Libertação de recursos e limpeza após ctlr c... \n");
	#endif

	signal(SIGINT, ctrl_c); // Garante que está à espera do SIGINT
	destroi_pool(); // Destói a pool de threads
    kill(processos[1], SIGKILL); // 

	// Fechar o pipe de escrita das estatísticas
	close(fd);
	// Desmapeia a memória mapeada
	munmap(local_domain_mmf, get_stat(fdin));
	// Fecha o ficheiro "localdns"
	close(fdin);
   
    // Liberta o named pipe
    unlink(configuracoes->named_pipe_estat);
    // Fecha o pipe de leitura das estatísticas
    close(fd_estatisticas_read);

    shmdt(configuracoes); // Desmapeia a memória partilhada das configurações 
    shmctl(shmid, IPC_RMID, NULL); // Destrói o segmento de memória partilhada 
  	sem_close(mem); // Fecha o semáforo das configurações
  	sem_close(mmf); // Fecha o semáforo do memory mapped file que contém os IPs locais

  	printf("\nServer terminating\n");
	close(sockfd); //Fecha o socket
	exit(0);
}


//Funçao com boolean para saber se esta em modo de manutenção e se estiver volta a ler o ficheiro de configurações
void modo_manutencao(int sig){
	if (configuracoes->manutencao == true){
		configuracoes->manutencao =false;
		sem_wait(mem); 
		read_config_file(); // Lê o ficheiro de configurações
		sem_post(mem);
		#ifdef DEBUG
		printf("DEBUG: Sai da manutencao e li ficheiro!!!\n");
		#endif
	}
	else{
		configuracoes->manutencao = true;
		#ifdef DEBUG
		printf("DEBUG: Entrei na manutencao!!!\n");
		#endif
	}
}

//Cria a pool de threads e inicializa as filas de espera
void cria_pool(int num_workers){ 
	int i;
	// Se ocorrer um erro na alocação de memória, imprime uma mensagem de erro e sai
	if((pool_main = (threadpool) malloc(sizeof(poolthreads))) == NULL){
		printf("ERRO na alocação de memória\n");
		exit(1);
	}

	// Inicialização com o número de threads lidas do ficheiro de configurações
	pool_main->num_threads = num_workers;

	// Aloca o espaço de memória necessário para o número de threads que queremos
	//Se ocorrer um erro na alocação de memória, imprime uma mensagem de erro e sai
	if((pool_main->threads = (pthread_t*) malloc(num_workers * sizeof(pthread_t))) == NULL){
		printf("ERRO na alocação de memória\n");
		exit(1);
	}

	// Alocamos o espaço necessário para guardarmos os id's das threads
	// Se ocorrer um erro na alocação de memória, imprime uma mensagem de erro e sai
	if((pool_main->ids = (int*) malloc(num_workers * sizeof(int))) == NULL){
		printf("ERRO na alocação de memória\n");
		exit(1);
	}

	//Inicialização das filas de espera
	pool_main->num_requests_prio = 0; // Número de pedidos prioritários por tratar
	pool_main->head_prio = NULL; // Fila dos prioritários

	pool_main->num_requests = 0; // Número de pedidos normais por tratar
	pool_main->head = NULL; // Fila de pedidos normais
	
	pool_main->flag_fechada = 0; // Flag que permite ou não a recepção de mais pedidos
	pool_main->flag_shutdown = 0; // Indica que o sistema vai fechar

	pthread_mutex_init(&(pool_main->lock), NULL); // Inicializa o mutex 
	pthread_cond_init(&(pool_main->not_empty), NULL); // Inicializa a variável de condição not_empty
	pthread_cond_init(&(pool_main->empty), NULL); // Inicializa a variável de condição empty

	// Criação das threads da pool
	for(i=0; i<num_workers; i++){
		#ifdef DEBUG
		printf("DEBUG: A criar a thread: %d\n",i);
		#endif 

		// Cria as threads e guarda os seus ID's
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
		// Exclusão mútua  enquanto as threads estão a ir buscar pedidos
		pthread_mutex_lock(&(pool_main->lock));

		while(pool_main->num_requests_prio == 0 && pool_main->num_requests == 0 && (!pool_main->flag_shutdown)){ // Não existem pedidos na fila de espera e a pool não vai ser destruída
			#ifdef DEBUG
			printf("DEBUG: Thread: %d --A aguardar por pedidos\n", id);
			#endif
			// Como não tem pedidos desbloqueia o mutex e fica à espera da variável not empty
			pthread_cond_wait(&(pool_main->not_empty), &(pool_main->lock)); // Aguarda por pedidos
		}
		if(pool_main->flag_shutdown){ //A pool vai ser destruída
			pthread_mutex_unlock(&(pool_main->lock));
			#ifdef DEBUG
			printf("DEBUG: A pool vai ser destruida Thread: %d --Vai ser destruida\n", id);
			#endif
			
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

		#ifdef DEBUG
		printf("A analisar pedido recebido: %s\n", novo_pedido->buffer);
		#endif
		
		// Atende o próximo pedido prioritário
		if(novo_pedido->tipo_dominio == 1)
			send_local(novo_pedido);
		
		// Atende o próximo pedido secundário
		else if(novo_pedido->tipo_dominio == 2)
			send_extern(novo_pedido);

		free(novo_pedido);
		//wait(NULL);
		//podia não estar aqui mas assim pode evitar-se que as threads fiquem bloqueadas no while à espera de trabalho
		sleep(3);
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
	//Pedidos prioritários
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
	//Pedidos secundários
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
 * e as threads da pool terminam a sua execução */
int destroi_pool(){
	#ifdef DEBUG
	printf("DEBUG: Destruir pool...\n");
	#endif
	int i;
	request* aux;

	// Bloqueia o mutex
	pthread_mutex_lock(&(pool_main->lock));

	pool_main->flag_fechada = 1;
	//ERRO: Devia existir dois whiles para cada uma das filas, porque uma pode ficar vazia primeiro que a outro. Tambem deviam existir duas variaveis empty, uma para cada fila
	// Aguarda que os pedidos a ser atendidos de momento fiquem concluídos. No código da entrega esquecemo-nos da condição para a fila dos prioritários
	while(pool_main->num_requests != 0 && pool_main->num_requests_prio != 0)
		//Ficam à espera do broadcast do empty e o mutex é libertado enquanto espera para as threads poderem trabalhar
		pthread_cond_wait(&(pool_main->empty), &(pool_main->lock));

	pool_main->flag_shutdown = 1;
	pthread_mutex_unlock(&(pool_main->lock));

	// "Acorda" todas as threads para que possam verificar a flag flag_shutdown
	// Ao fazer broadcast do not_empty as threads vão ser desbloqueadas e avaliar a condição shutdown
	pthread_cond_broadcast(&(pool_main->not_empty));

	// Espera por todas as threads da pool que terminem
	for(i=0; i<pool_main->num_threads; i++)
		pthread_join(pool_main->threads[i], NULL);

	// Liberta os recursos
	#ifdef DEBUG
	printf("DEBUG: A libertar recursos...\n");
	#endif
	free(pool_main->threads);
	free(pool_main->ids);
	
	// Liberta a fila prioritária
	while(pool_main->head_prio!=NULL){
		aux = pool_main->head_prio->next;
		pool_main->head_prio = pool_main->head_prio->next;
		free(aux);
	}
	// Liberta a fila normal
	while(pool_main->head!=NULL){
		aux = pool_main->head->next;
		pool_main->head = pool_main->head->next;
		free(aux);
	}
	free(pool_main);

	#ifdef DEBUG
	printf("DEBUG: Pool destruida\n");
	#endif
	return 0;
} 


// Imprime as estatísticas 
void *imprime_estatisticas(){
	signal(SIGINT, ctrl_c_esta); // Quando recebe o sinal do tipo SIGINT (ctr_c) chama a função ctrl_c_esta
	while(1){
		sleep(30); // Sleep(30) porque tem que imprimir as estatisticas a cada 30 segundos
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
	sleep(2); // Sleep(2) porque primeiro tem que ser criado o pipe para escrever
	// Inicializa a estrutura das estatísticas a 0
	msg.num_pedidos_recusados = 0;
	msg.num_total_pedidos_processados = 0;
	msg.num_enderecos_local = 0;
	msg.num_enderecos_externo = 0;
	FILE* fich;
	char buf[MAX_BUF];
	// Cria a thread para imprimir as estatísticas
	pthread_create(&thread_estatisticas, NULL, &imprime_estatisticas, NULL); // thread_estatisticas -> Nome da thread
																			 // NULL -> Não há atributos novos
																			 // imprime_estatisticas -> Nome da função "gerida" pela thread
	
	#ifdef DEBUG
	printf("DEBUG: Criando pipe ler...\n");
	#endif


	// Abre o pipe das estatísticas para ler
	fd_estatisticas_read = open(configuracoes->named_pipe_estat, O_RDONLY);

	while(1){
		// Lê do pipe
		read(fd_estatisticas_read, buf, MAX_BUF); // fd_estatisticas_read -> nome do pipe // buf -> buffer onde guardamos o que vem do pipe
		set_hora_data(hora_actual);
		//Incrementa o numero de pedidos respectivamente
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
		memset(&buf, 0, sizeof(buf)); // Limpamos o buffer
	}
	exit(0);
}


// Processo Filho - Gestão da configurações executa primeiro que o das estatísticas
void gestao_config(){
	sem_wait(mem); // Se o semáforo está a 1 -> decrementa e continua . Caso esteja a 0 bloqueia
    read_config_file(); // Lê o ficheiro de configurações para a memória partilhada
    sem_post(mem); // Incrementa o semáforo
    signal(SIGUSR1, modo_manutencao); // Caso receba um sinal do tipo SIGUSR1 entra em modo de manutenção
    while(1){ // Mantém o processo gestao_config "vivo" para poder receber o sinal SIGUSR1
    }
   	
}

// Vê o tamanho do ficheiro a ser mapeado para a memória
int get_stat(int fdin){
	struct stat pstatbuf;	
	if (fstat(fdin, &pstatbuf) < 0){
		fprintf(stderr,"fstat error\n");
		exit(1);
	}
	return pstatbuf.st_size;
}

// Enviar a resposta quando se trata de um pedido local
void send_local(request* pedido){
	#ifdef DEBUG
	printf("DEBUG: ENVIAR RESPOSTA LOCAL\n");
	#endif

	char localdomains[MAX_BUF], local_ip[MAX_BUF];
	int i, k, j, we_are_in_answer_section = 0;

	sem_wait(mmf);
	for(i = 0; i < strlen(local_domain_mmf); i++){
		k = 0;
		while(local_domain_mmf[i] != ' '){
			localdomains[k] = local_domain_mmf[i];
			i++;
			k++;
		}
		localdomains[k] = '\0';
		
		if (strcmp(localdomains, pedido->buffer) == 0){
			j = 0;
			while ((local_domain_mmf[i] != '\n')){
				if (local_domain_mmf[i] != ' '){
					local_ip[j] = local_domain_mmf[i];
					j++;
				}
				i++;
			}
			we_are_in_answer_section = 1;
			break;
		}
		else{
			while (local_domain_mmf[i] != '\n')
				i++;
		} 
	}
	sem_post(mmf);

	if (we_are_in_answer_section == 0)
    	sendReply(pedido->query_id, pedido->buffer, inet_addr("0.0.0.0"), pedido->socket, pedido->dest,3); // 3 - code do dig para non existing domain
    else
    	sendReply(pedido->query_id, pedido->buffer, inet_addr(local_ip), pedido->socket, pedido->dest,0); // 0 - tudo normal
}

// Enviar resposta quando se trata de um pedido externo
void send_extern(request* pedido){
	int i = 0, j = 0;
	#ifdef DEBUG
	printf("DEBUG: ENVIAR RESPOSTA EXTERNA\n");
	#endif


    char buf[MAX_BUF], finds_ip[MAX_BUF];
    char *str1 = "dig ";
    int we_are_in_answer_section = 0;
    FILE *fp;
    // Constrói o comando dig para fazer o dig do pedido externo
    char cmd[strlen(str1) + strlen(pedido->buffer) + 1];
    strcpy(cmd, str1);
    strcat(cmd, pedido->buffer);
    // Executa o dig 
    if ((fp = popen(cmd, "r")) == NULL){
        printf("Error opening pipe!\n");
        return;
    }

    while (fgets(buf, MAX_BUF, fp) != NULL){
        if (we_are_in_answer_section == 1){
    		while (buf[i] != 'A'){
    			i++;
    		}
    		while(!isdigit(buf[i])){
    			i++;
    		}
    		if (isdigit(buf[i])){
				while(buf[i] != '\0'){
					finds_ip[j] = buf[i]; 
					j++;
					i++;
				}
				finds_ip[j] = '\0';
        	}
        	break;
        }
        if(strstr(buf, "ANSWER SECTION") != NULL) {
		    we_are_in_answer_section = 1;
		}
    }
    if (we_are_in_answer_section == 0)
    	sendReply(pedido->query_id, pedido->buffer, inet_addr("0.0.0.0"), pedido->socket, pedido->dest,3); // Se não obtiver resposta 
    else
    	sendReply(pedido->query_id, pedido->buffer, inet_addr(finds_ip), pedido->socket, pedido->dest,0); // Se obtiver resposta
   	
   	wait(NULL);
    pclose(fp);
}


int main( int argc , char *argv[]){
	set_hora(hora_arranque); // Determina a hora de arranque do Servidor
	int i, j, k, recusa = 0;
	char buffer[MAX_BUF];


	// Verifica o número de argumentos
	if(argc!=2){
		printf("Usage: %s <port>\n", argv[0]);
		exit(1);
	}
	port = atoi(argv[1]);

	configuracoes = malloc(sizeof(mem_config));

	// Cria e mapeia a região de memória partilhada das configurações
	#ifdef DEBUG
	printf("DEBUG: Criando memória partilhada...\n");
	#endif

	shmid = shmget(IPC_PRIVATE, sizeof(mem_config), IPC_CREAT|0700); //shmget cria o espaço de memória e devolve o id
	if(shmid==-1){ 
		perror("ERRO ao criar memória partilhada");
		exit(1);
	}
    configuracoes = (mem_config*) shmat(shmid, NULL, 0); //mapeia o espaço de memória criado (id devolvido pelo shmget) e retorna o endereço da memória mapeada
    if(configuracoes == (mem_config*) -1){
    	perror("ERRO no shmat");
    	exit(1);
    }
    // Inicializa e abre o semáforo que controla o acesso à memória partilhada das configurações
	sem_unlink("MEM"); //remove semáforo com o mesmo nome
	mem = sem_open("MEM", O_CREAT|O_EXCL, 0700, 1); //Cria o semáforo.. O_CREAT - > Caso não existe cria  O_EXCL -> Assegura-se de que criou o semáforo 1 -> Estado inicial do semáforo
	if(mem==SEM_FAILED){
		perror("ERRO na criação do semáforo");
		exit(1);
	}

	// Mapear o ficheiro localdns.txt para memória (Memory mapped files)
	#ifdef DEBUG
	printf("DEBUG: Mapear o ficheiro localdns.txt para memória...\n");
	#endif

	// Abre o ficheiro localdns para leitura
	if ( (fdin = open("localdns.txt", O_RDONLY)) < 0){ 
		fprintf(stderr,"Can't open localdns.txt for reading");
		exit(1);
	}
	// Tamanho do ficheiro que vamos mapear
	size = get_stat(fdin);

	// Mapeia o ficheiro
	if ((local_domain_mmf = mmap(0, size, PROT_READ, MAP_FILE | MAP_PRIVATE, fdin, 0)) == (caddr_t) -1){ // mmap -> mapeia o ficheiro e retorna o endereço 
		fprintf(stderr,"mmap error for input\n");													     // PROT_READ -> O ficheiro está protegido para leitura
		exit(1);																						 // MAP_PRIVATE -> Creates private copy-on-write
	}																									 // MAP_FILE -> Compatibility flag. Ignored.
																									     // fdin -> Descritor do ficheiro 

	// Inicializa e abre o semáforo que controla o acesso ao memory mapped file
	sem_unlink("MMF");
	mmf = sem_open("MMF", O_CREAT|O_EXCL, 0700, 1);
	if(mmf==SEM_FAILED){
		perror("ERRO na criação do semáforo");
		exit(1);
	}

	// Cria os processos gestor de configurações e gestor de estatisticas
	for(i=0; i<2; i++){
		if((processos[i] = fork()) == 0){
			switch(i){
				case 0:
					printf("\nNumero do processo de Gestão de Gonfigurações: %ld\n\n",(long)getpid());
					gestao_config();
					break;
				case 1:
					gestao_estatisticas();
					exit(0);
					break;
			}
		}
	}
	sleep(1); // Espera que os processos sejam criados
	#ifdef DEBUG
	printf("DEBUG: Criando pool...\n");
	#endif
	cria_pool(configuracoes->num_threads);

	#ifdef DEBUG
	printf("DEBUG: Criando pipe para escrever...\n");
	#endif

	// Criar um named pipe
    mkfifo(configuracoes->named_pipe_estat, 0666);
    fd = open(configuracoes->named_pipe_estat, O_WRONLY);

    signal(SIGINT, ctrl_c); // Tratamento do sinal SIGINT



	unsigned char buf[65536], *reader;
	int stop;
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
		recusa = 0;
		printf("\n\n-- Waiting for DNS message --\n\n");
		if(recvfrom (sockfd,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , &len) < 0) {
			printf("Error while waiting for DNS message. Exiting...\n");
			exit(1);
		}
		
		printf("DNS message received\n");
		
		// Process received message
		dns = (struct DNS_HEADER*) buf;
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


		//Verifica se o pedido é aceite(adiciona-o) ou é recusado
		if (strstr(query.name, configuracoes->local_domain) != NULL){ // Compara a query name com o local domain
			sprintf(buffer,"local"); // Copia a string para o buffer
	 		write(fd, buffer, sizeof(buffer)); // Escreve para o pipe do gestor de estatísticas
	 		adiciona_pedido(1, sockfd, query.name, dns->id, dest); // Adiciona o pedido de tipo 1 (prioritário) e as variáveis para enviar a resposta
	 		recusa = 1; // O pedido já não vai ser recusado
			//Adiciona pedido fila prioritaria
		}

		if (!configuracoes->manutencao){ // Só entra aqui quando não está em manutenção. Em manutenção só tratamos os locais, os restantes são recusados
			if(configuracoes->num_domain_extern != 0){ // Se existirem domínios externos
				for(i=0; i<configuracoes->num_domain_extern;i++){ // Percorremos os domínios
					if (strstr(query.name, configuracoes->domains[i]) != NULL){ // Vemos se o nome do domínio está no pedido
						sprintf(buffer,"externo"); // Copia a string para o buffer
		 				write(fd, buffer, sizeof(buffer)); // Escreve para o pipe do gestor de estatísticas
		 				adiciona_pedido(2, sockfd, query.name, dns->id, dest); // Adiciona o pedido de tipo 2 (externo) e as variáveis para enviar a resposta
		 				recusa = 1; // O pedido já não vai ser recusado
		 				//Adiciona pedido a fila secundaria
		 				break;
					}
				}
			}
		}
		//O pedido é recusado
		if (recusa == 0){
			sprintf(buffer,"recusa");
	 		write(fd, buffer, sizeof(buffer)); // Escreve para o pipe das estatísticas que foi recusado
	 		printf("PEDIDO RECUSADO\n");
			sendReply(dns->id, query.name, inet_addr("10.0.0.2"), sockfd, dest,5); // O 5 é o error code do dig para indicar que foi recusado
		}
		
		// ****************************************
		// Example reply to the received QUERY
		// (Currently replying 10.0.0.2 to all QUERY names)
		// ****************************************
		//sendReply(dns->id, query.name, inet_addr("10.0.0.2"), sockfd, dest); //Caso não pertença ao localdns.txt....
		
	}
	
	

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
void sendReply(unsigned short id, unsigned char* query, int ip_addr, int sockfd, struct sockaddr_in dest, int code) {
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
		rdns->rcode = code;
		rdns->q_count = 0;
		if (code == 5)
			rdns->ans_count = 0;
		else
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