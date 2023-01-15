#include <signal.h>
#include "SpectaProbe.h"

void sig_handler(int signo)
{
	uint16_t intfCounter, routerCounter;

	if(signo == SIGTERM || signo == SIGINT)
	{
		printf("\n Probe Shutdown Initiated....\n");

		/* Stop Packet */
		for(intfCounter = 0; intfCounter < MAX_INTERFACE_SUPPORT; intfCounter ++)
			Global::PACKET_PROCESSING[intfCounter] = false;

		/* TCP SM */
		for(uint16_t i = 0; i < Global::TCP_SESSION_MANAGER_INSTANCES; i++)
			Global::TCP_SESSION_MANAGER_RUNNING_STATUS[i] = false;

		sleep(1);

		/* TCP Flusher */
		for(uint16_t i = 0; i < Global::NO_OF_TCP_FLUSHER; i++)
			Global::TCP_FLUSHER_RUNNING_STATUS[i] = false;

		sleep(1);

		/* UDP SM */
		for(uint16_t i = 0; i < Global::UDP_SESSION_MANAGER_INSTANCES; i++)
			Global::UDP_SESSION_MANAGER_RUNNING_STATUS[i] = false;

		sleep(1);

		/* UDP Flusher */
		for(uint16_t i = 0; i < Global::NO_OF_UDP_FLUSHER; i++)
			Global::UDP_FLUSHER_RUNNING_STATUS[i] = false;

		sleep(1);

		/* DNS SM */
		for(uint16_t i = 0; i < Global::DNS_SESSION_MANAGER_INSTANCES; i++)
			Global::DNS_SESSION_MANAGER_RUNNING_STATUS[i] = false;

		sleep(1);

		/* DNS Flusher */
		for(uint32_t i = 0; i < Global::NO_OF_DNS_FLUSHER; i++)
			Global::DNS_FLUSHER_RUNNING_STATUS[i] = false;

		sleep(1);

		/* UNM SM */
		for(uint16_t i = 0; i < Global::UNM_SESSION_MANAGER_INSTANCES; i++)
			Global::UNM_SESSION_MANAGER_RUNNING_STATUS[i] = false;

		sleep(1);

		/* Un Mapped */
		for(uint16_t i = 0; i < Global::NO_OF_UNM_FLUSHER; i++)
			Global::UNM_FLUSHER_RUNNING_STATUS[i] = false;

		sleep(1);

		/* Routers */
		for(uint16_t infCounter = 0; infCounter < Global::NO_OF_INTERFACES; infCounter++)
			for(uint16_t routeCounter = 0; routeCounter < Global::ROUTER_PER_INTERFACE[infCounter]; routeCounter++)
				Global::PKT_ROUTER_RUNNING_STATUS[infCounter][routeCounter] = false;

		sleep(1);

		/* Packet Listener */
		for(uint16_t infCounter = 0; infCounter < Global::NO_OF_NIC_INTERFACE; infCounter++)
			Global::PKT_LISTENER_RUNNING_STATUS[infCounter] = false;

		sleep(1);

		/* Stats Log & Timer */
		Global::PROBE_STATS_RUNNING_STATUS = false;

		/* Main Thread */
		Global::PROBE_RUNNING_STATUS = false;
	}
}

int main(int argc, char *argv[])
{
	sleep(2);

	/* Initialize all the Locks */
	mapDnsLock::count 		= 1;

	if (signal(SIGTERM, sig_handler) == SIG_ERR || signal(SIGINT, sig_handler) == SIG_ERR)
		printf(" SpectaProbe Can't Received Signal...\n");

	timeval curTime;
	struct tm *now_tm;

	Global::PROBE_RUNNING_STATUS = true;
	SpectaProbe *spectaProbe = new SpectaProbe("probe.config");
	spectaProbe->start();

	printf("  **** SpectaProbe Exiting...Please wait... ***** \n");
}
