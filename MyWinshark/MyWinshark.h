#pragma once

#include <QtWidgets/QWidget>
#include <pcap.h>
#include <QTimer>
#include <QThread>
#include <QThreadPool>
#include <QByteArray>
#include "Constant.h"
#include "Sniffer.h"
#include "ui_MyWinshark.h"
#include "AdapterChoose.h"
class Sniffer;

class MyWinshark : public QWidget
{
    Q_OBJECT

public:
    MyWinshark(QWidget *parent = nullptr);
    void setConnect();
    void setSniffer();
    void setWindow();
    void setinformation(QString type,int number);//չʾ��ϸ��Ϣ
    void setEthernet(int number);
    void setHex(int number);
    void chooseadapter(QString description) { this->adapter = description; };
    void startSniffer();
    unsigned int setIP(int number);
    Q_INVOKABLE void setitem(QStringList summary, QByteArray data);//���շ����̴߳��������ݰ��͸�Ҫ��Ϣ
    ~MyWinshark();

private:
    int count=0;
    QMap<QString, pcap_if_t*> adapters; //����������Ϣ <description adapter>
    QHash<int, QByteArray> information; //�������ݰ�
    Sniffer* sniffer = NULL;
    QVector<QStringList> summary;
    QTimer* timer = NULL;
    QString adapter ;
    AdapterChoose* choose = NULL;
    Ui::MyWinsharkClass ui;
signals:
    void endSniff();
};
