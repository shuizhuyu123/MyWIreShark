#pragma once

#include <QObject>
#include <QTHreadPool>
#include <pcap.h>
#include "MyWinshark.h"
#include "Analyse.h"
class MyWinshark;
class Sniffer  : public QObject
{
	Q_OBJECT

public:
	Sniffer();
	QMap<QString, pcap_if_t*> findAdapters();
	void startSniff(pcap_if_t* adapter, MyWinshark* window);
	void endSniff() { flag = 0; }
	~Sniffer();
private:
	int flag;
};
