#pragma once

#include <QObject>
#include <QTHreadPool>
#include <pcap.h>
#include "MyWinshark.h"
#include "Analyse.h"
class MyWinshark;
class Sniffer  : public QThread
{
	Q_OBJECT

public:
	Sniffer(MyWinshark* winodw);
	QMap<QString, pcap_if_t*> findAdapters();
	void startSniff(pcap_if_t* adapter, MyWinshark* window);
	void setAdapter(pcap_if_t* adapter) { this->adapter = adapter; }
	void endSniff();
	~Sniffer();
protected:
	virtual void run() override;
private:
	pcap_if_t* allAdapters=NULL;
	boolean flag;
	pcap_if_t* adapter;
	MyWinshark* window;
signals:
	void finished();
};
