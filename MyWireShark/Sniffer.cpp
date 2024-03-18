#include "Sniffer.h"

Sniffer::Sniffer(MyWireShark* window):window(window)
{

}

QMap<QString, pcap_if_t*> Sniffer::findAdapters()
{	
	QMap<QString, pcap_if_t*> adapters;
	pcap_if_t* p = NULL;
	char errorbuff[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allAdapters, errorbuff) != -1) {
		p = allAdapters;
		for (p; p != NULL; p = p->next) {
			adapters.insert(QString(p->description), p);
		}
		return adapters;
	}
}

void Sniffer::run()
{
	startSniff(adapter,window);
}

void Sniffer::startSniff(pcap_if_t* adapter,MyWireShark* window)
{	
	flag = true;
	pcap_t*handle = pcap_open(adapter->name, 65534, 1, PCAP_OPENFLAG_PROMISCUOUS, 0, 0);
	pcap_pkthdr* Packet_Header;    
	const u_char* Packet_Data;    
	int retValue;
	while (flag&&(retValue = pcap_next_ex(handle, &Packet_Header, &Packet_Data)) >= 0) {
		if (retValue == 0)
			continue;
		else {
			QByteArray array;
			array.resize(Packet_Header->len);
			memcpy(array.data(), Packet_Data, Packet_Header->caplen);
			Analyse* analyse = new Analyse(std::move(array), Packet_Header->caplen, window);
			QThreadPool::globalInstance()->start(analyse);
		}
	}
}

void Sniffer::endSniff()
{
	flag = false;
	QThreadPool::globalInstance()->clear();
	QThreadPool::globalInstance()->waitForDone();
}

Sniffer::~Sniffer()
{
	pcap_freealldevs(allAdapters);
}
