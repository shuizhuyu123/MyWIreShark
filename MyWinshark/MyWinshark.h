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
class Sniffer;

class MyWinshark : public QWidget
{
    Q_OBJECT

public:
    MyWinshark(QWidget *parent = nullptr);
    void setConnect();
    void setSniffer();
    void setWindow();
    void setinformation(QString type,int number);
    void setEthernet(int number);
    unsigned int setIP(int number);
    Q_INVOKABLE void setitem(QStringList summary, QByteArray data);
    ~MyWinshark();

private:
    int count=0;
    QMap<QString, pcap_if_t*> adapters;
    QMap<int, QByteArray> information;
    Sniffer* sniffer = NULL;
    pcap_if_t* adapter = NULL;
    QVector<QStringList> summary;
    QTimer* timer = NULL;
    Ui::MyWinsharkClass ui;
signals:
    void endSniff();
};
