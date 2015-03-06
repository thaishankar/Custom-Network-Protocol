#include "header.h"

void CreateTable()
{
	Routing_Table['B'][0]='B';
	Routing_Table['B'][1]=0;
	
	Routing_Table['A'][0]='A';
	Routing_Table['A'][1]=4;
	
	Routing_Table['C'][0]='C';
	Routing_Table['C'][1]=3;
}

char Route(char next_hop)
{
	int i;
	for(i=0;i<256;i++)
	{
		if(Routing_Table[i][0]==next_hop)
			return (char)(Routing_Table[i][1]);
	}
	return NULL;
}
	
	
	

