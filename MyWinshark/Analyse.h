#pragma once

#include <QByteArray>
#include <QRunnable>
#include <pcap.h>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <QDebug>
#include "MyWinshark.h"
#include "Constant.h"
#pragma comment(lib, "Ws2_32.lib")
class MyWinshark;
class Analyse  : public QRunnable
{
public:
	Analyse(pcap_pkthdr* Packet_Header, const UCHAR* Packet_Data, MyWinshark* window);
	virtual void run() override;
	void unpack();
	void unpackIP();
	~Analyse(); 
private:
	QByteArray content;
	pcap_pkthdr* Packet_Header = NULL;
	const UCHAR * Packet_Data = NULL;
	MyWinshark* window;
};
