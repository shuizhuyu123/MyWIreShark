#pragma once

#include <QObject>
#include <QTHreadPool>
#include <pcap.h>
#include "MyWireShark.h"
#include "Analyse.h"
class MyWireShark;
class Sniffer  : public QThread
{
	Q_OBJECT

public:
	Sniffer(MyWireShark* winodw);
	QMap<QString, pcap_if_t*> findAdapters();
	void startSniff(pcap_if_t* adapter, MyWireShark* window);
	void setAdapter(pcap_if_t* adapter) { this->adapter = adapter; }//��������
	void endSniff();
	~Sniffer();
protected:
	virtual void run() override;
private:
	pcap_if_t* allAdapters=NULL;
	boolean flag;
	pcap_if_t* adapter;
	MyWireShark* window;//���ݸ��̷߳�����Ϣ
	
signals:
	void finished();
};
