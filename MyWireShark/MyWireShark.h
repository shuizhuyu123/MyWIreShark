#pragma once

#include <QtWidgets/QWidget>
#include <pcap.h>
#include <QTimer>
#include <QThread>
#include <QThreadPool>
#include <QByteArray>
#include <QMessageBox>
#include <QFileDialog>
#include <thread>
#include <QMutex>
#include <QtConcurrent>
#include <QProgressDialog>
#include "Constant.h"
#include "Sniffer.h"
#include "ui_MyWireShark.h"
#include "AdapterChoose.h"
#include "ProtocalData.h"
class Sniffer;

class MyWireShark : public QWidget
{
    Q_OBJECT

public:
    MyWireShark(QWidget *parent = nullptr);
    void setConnect();
    void setSniffer();
    void setWindow();
    void setHex(int number);
    void setInformation(int number);
    void addProtocolItemsToTreeWidget(QTreeWidget* treeWidget, const QVector<ProtocolItem>& items, QTreeWidgetItem* parent = nullptr);
    void chooseadapter(QString description) { this->adapter = description; };
    void startSniffer();
    void save(QString filePath);
    void saveProtocolItems(const QVector<ProtocolItem>& items, QTextStream& out, int level=2);
    Q_INVOKABLE void setitem(QStringList summary, ProtocolData protocol);//接收分析线程传来的数据包和概要信息
    ~MyWireShark();

private:
    int count=0;
    QMap<QString, pcap_if_t*> adapters; //保存网卡信息 <description adapter>
    Sniffer* sniffer = nullptr;
    QVector<QStringList> summary;
    QHash<int,ProtocolData>protocols;
    QTimer* timer = nullptr;
    QString adapter ;
    AdapterChoose* choose = nullptr;
    QProgressDialog* progressDialog = nullptr;
    Ui::MyWireSharkClass ui;
signals:
    void progressUpdated(int current);
    void endSniff();
};
