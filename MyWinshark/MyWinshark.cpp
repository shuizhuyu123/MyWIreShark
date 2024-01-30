#include "MyWinshark.h"

MyWinshark::MyWinshark(QWidget *parent)
    : QWidget(parent)
{
    ui.setupUi(this);
    setSniffer();
    setConnect();
    setWindow();
}

void MyWinshark::setSniffer()
{
    sniffer = new Sniffer();
    adapters = sniffer->findAdapters();
    thread = new QThread();
    timer = new QTimer(this);
    
}
void MyWinshark::setWindow()
{
    QStringList list;
    list << "NO" <<u8"源ip地址" <<u8"目的ip地址" <<u8"协议" <<u8"长度";
    ui.tableWidget->setHorizontalHeaderLabels(list);
    ui.tableWidget->setColumnWidth(0, 100);
    ui.tableWidget->setColumnWidth(1, 300);
    ui.tableWidget->setColumnWidth(2, 300);
    ui.tableWidget->setColumnWidth(3, 200);

}
void MyWinshark::setConnect()
{   
    
    connect(ui.start, &QToolButton::clicked, this, [=] {
        adapter = adapters["Network adapter 'MediaTek Wi-Fi 6 MT7921 Wireless LAN Card' on local host"];
        sniffer->moveToThread(thread);
        connect(thread, &QThread::started, sniffer, [=] {
            sniffer->startSniff(adapter, this);
            });
        thread->start();
        timer->start(1000);
    });
    connect(ui.end, &QToolButton::clicked, this, [=] {
        timer->stop();
        emit endSniff();
        QThreadPool::globalInstance()->clear();
        QThreadPool::globalInstance()->waitForDone();
        thread->quit();
    });
    connect(timer, &QTimer::timeout, this, [=] {
        for (auto item : summary) {
            int rowcount = item[0].toInt();
            ui.tableWidget->setRowCount(count);
            for (int i = 0; i < 5; i++) {
                ui.tableWidget->setItem(rowcount, i, new QTableWidgetItem(item[i]));
            }
        }
        summary.clear();
    });
}
void MyWinshark::setitem(QStringList summary, QByteArray data)
{   
    information.insert(count, data);
    summary.push_front(QString::number(count++));
    this->summary.push_back(summary);
}

MyWinshark::~MyWinshark()
{
    QThreadPool::globalInstance()->clear();
    QThreadPool::globalInstance()->waitForDone();
    thread->quit();
}
