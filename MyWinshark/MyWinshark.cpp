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
    connect(ui.tableWidget, &QTableWidget::itemClicked, this, [=](QTableWidgetItem *item) {
        ui.treeWidget->clear();
        int row = item->row();
        int number = ui.tableWidget->item(row, 0)->text().toInt();
        QString type = ui.tableWidget->item(row, 3)->text();
        setinformation(type, number);
    });
}
void MyWinshark::setitem(QStringList summary, QByteArray data)
{   
    information.insert(count, data);
    summary.push_front(QString::number(count++));
    this->summary.push_back(summary);
}
void MyWinshark::setEthernet(int number) {
    ether_header* eth = (ether_header*)information[number].constData();
    QStringList list;
    QString src = "%1:%2:%3:%4:%5:%6";
    QString dst = "%1:%2:%3:%4:%5:%6";
    for (int i = 0; i < 6; i++) {
        src = src.arg(QString::number(eth->ether_shost[i], 16));
        dst = dst.arg(QString::number(eth->ether_dhost[i], 16));
    }
    list << "Ethernet " << "src:" << src << "dst:" << dst;
    QTreeWidgetItem *item = new QTreeWidgetItem(list);
    ui.treeWidget->addTopLevelItem(item);
    QList<QTreeWidgetItem*>children;
    
    list.clear();
    list << "Source:" << src;
    children.append(new QTreeWidgetItem(list));

    list.clear();
    list << "Destination:" << dst;
    children.append(new QTreeWidgetItem(list));

    list.clear();
    list << "Type:" << "0x" + QString::number(ntohs(eth->ether_type), 16).rightJustified(4, '0');
    children.append(new QTreeWidgetItem(list));

    item->addChildren(children);

}
void MyWinshark::setIP(int number) {
    iphead* ipheader = (iphead*)(information[number].constData() + 14);
    QStringList list;
    char src[32], dst[32];
    inet_ntop(AF_INET, &ipheader->m_ulSrcIP, src, sizeof(src));
    inet_ntop(AF_INET, &ipheader->m_ulDestIP, dst, sizeof(dst));
    list << "Internet Protocal version " + QString::number(ipheader->version)<< "Src:" << src << "Dst" << dst;
    QTreeWidgetItem* item = new QTreeWidgetItem(list);
    ui.treeWidget->addTopLevelItem(item);
    QList<QTreeWidgetItem*>children;

    list.clear();
    list << "Version:" << QString::number(ipheader->version, 2).rightJustified(4, '0')+"....";
    children.append(new QTreeWidgetItem(list));

    list.clear();
    list << "Header length:" << "...."+QString::number(ipheader->m_HDlen,2).rightJustified(4, '0');
    children.append(new QTreeWidgetItem(list));

    list.clear();
    list << "Tos:" << QString::number(ipheader->m_byTOS, 2).rightJustified(8, '0');
    children.append(new QTreeWidgetItem(list));

    list.clear();
    list << "Total length:" << QString::number(ntohs(ipheader->m_byTotalLen));
    children.append(new QTreeWidgetItem(list));

    list.clear();
    list << "Total length:" << QString::number(ntohs(ipheader->m_byTotalLen));
    children.append(new QTreeWidgetItem(list));

    list.clear();
    unsigned short flag = (ntohs(ipheader->m_usFlagFragOffset) >> 13) & 0x7;
    list << "Flag:" << QString::number(flag,2).rightJustified(3,'0')+". ....";
    children.append(new QTreeWidgetItem(list));

    list.clear();
    unsigned short fragOffset = ntohs(ipheader->m_usFlagFragOffset) & 0x1FFF;
    list << "Fragment Offset:" << "... " + QString::number(fragOffset, 2).rightJustified(13, '0');
    children.append(new QTreeWidgetItem(list));

    list.clear();
    list << "TTL:" << QString::number(ipheader->m_byTTL);
    children.append(new QTreeWidgetItem(list));

    list.clear();
    list << "Protocol:" << QString::number(ipheader->byProtocol);
    children.append(new QTreeWidgetItem(list));

    list.clear();
    list << "Checksum:" <<"0x"+QString::number(ntohs(ipheader->m_usHChecksum), 16).rightJustified(4, '0');
    children.append(new QTreeWidgetItem(list));

    item->addChildren(children);

}
void MyWinshark::setinformation(QString type, int number) {
    if (type == "TCP") {
        setEthernet(number);
        setIP(number);

    }
    if (type == "UDP") {
        setEthernet(number);
        setIP(number);
    }
    if (type == "ICMP") {

    }
}
MyWinshark::~MyWinshark()
{
    QThreadPool::globalInstance()->clear();
    QThreadPool::globalInstance()->waitForDone();
    thread->quit();
}
