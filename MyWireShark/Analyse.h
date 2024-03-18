#pragma once

#include <QByteArray>
#include <QRunnable>
#include <pcap.h>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <QDebug>
#include "ProtocalData.h"
#include "MyWireShark.h"
#include "Constant.h"
#pragma comment(lib, "Ws2_32.lib")
class MyWireShark;
class Analyse  : public QRunnable
{
public:
	Analyse(QByteArray&& byte, int cplen, MyWireShark* window);
	virtual void run() override;
	void unpack(const char* packet);
	void unpackIP(const char* packet);
	void unpackTCP(const char* packet,int len);
	void unpackUDP(const char* packet,int len);
	void unpackICMP(const char* packet,int len);
	void unpackHttp(const char* packet,int len);
	void unpackDNS(const char* packet, int len);
	void unpackSMTP(const char* packet, int len);
	void unpackSSDP(const char* packet, int len);
	void getNextArray(const char* pattern, int* next, int len);
	bool kmpSearch(const char* text, int textLen, const char* pattern, int patternLen);
	~Analyse();
private:
	ProtocolData content;
	QStringList root;
	QStringList summary;
	QVector<QStringList> children;
	QByteArray array;
	int len;
	int cplen;
	const UCHAR * Packet_Data = NULL;
	MyWireShark* window;
};
