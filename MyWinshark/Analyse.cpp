#include "Analyse.h"

Analyse::Analyse(pcap_pkthdr* Packet_Header,const UCHAR* Packet_Data,MyWinshark *window)
	: Packet_Header(Packet_Header),Packet_Data(Packet_Data),window(window)
{}
void Analyse::run() {
	
	content.resize(Packet_Header->len);
	memcpy(content.data(), Packet_Data, Packet_Header->caplen);
	unpack();
}
void Analyse::unpack() {
	ether_header* eth = (ether_header*)Packet_Data;
	switch (ntohs(eth->ether_type)) {
	case 0x0800: {
		unpackIP();
	}
	case 0x0806:{
		unpackARP();
	}
	}
}
void Analyse::unpackIP()
{
	iphead* ipheader = (iphead*)(Packet_Data + 14);
	char src[32], dst[32];
	QStringList summary;
	if (inet_ntop(AF_INET, &ipheader->m_ulSrcIP, src, sizeof(src)) && inet_ntop(AF_INET, &ipheader->m_ulDestIP, dst, sizeof(dst))) {
		summary << src << dst;
		switch (ipheader->byProtocol)
		{
		case 1: {
			summary << "ICMP"; 
			break;
		}
		case 2: {
			summary << "IGMP"; 
			break;
		}
		case 6: {
			summary << "TCP";
			break;
		}
		case 17: {
			summary << "UDP";
			break;
		}
		case 89: {
			summary << "OSPF";
			break;
		}
		default:{
			summary << "NONE";
			break;
		}
		}
		summary << QString::number(Packet_Header->caplen);
		QMetaObject::invokeMethod(window, "setitem", Qt::AutoConnection, Q_ARG(QStringList,summary), Q_ARG(QByteArray,content));
	}
	

}
Analyse::~Analyse()
{
	content.clear();
}
