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
    sniffer = new Sniffer(this);
    adapters = sniffer->findAdapters();
    timer = new QTimer(this);
    connect(this, &MyWinshark::endSniff, sniffer, &Sniffer::endSniff);
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
    
    ui.treeWidget->setColumnWidth(0, 200);
    ui.treeWidget->setColumnWidth(1, 200);

    ui.Hex->setColumnWidth(0, 50);
}
void MyWinshark::setConnect()
{   
    
    connect(ui.start, &QToolButton::clicked, this, [=](){
        QStringList list = adapters.keys();
        choose = new AdapterChoose(list);
        choose->setChoose(std::bind(&MyWinshark::chooseadapter, this, std::placeholders::_1));
        choose->setConfirm(std::bind(&MyWinshark::startSniffer, this));
        choose->show();
    });
    connect(ui.end, &QToolButton::clicked, this, [=] {
        ui.start->setEnabled(true);
        timer->stop();
        emit endSniff();
        sniffer->quit();
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
        ui.Hex->clear();
        int row = item->row();
        int number = ui.tableWidget->item(row, 0)->text().toInt();
        QString type = ui.tableWidget->item(row, 3)->text();
        setinformation(type, number);
        setHex(number);
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
    list << "Ethernet " << "src:"+src << "dst:"+dst;
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
void MyWinshark::startSniffer()
{
    information.clear();
    ui.tableWidget->clearContents();
    ui.treeWidget->clear();
    ui.Hex->clear();
    ui.start->setEnabled(false);
    sniffer->setAdapter(adapters[adapter]);
    sniffer->start();
    timer->start(1000);
}
unsigned int MyWinshark::setIP(int number) {
    iphead* ipheader = (iphead*)(information[number].constData() + 14);
    QStringList list;
    char src[32], dst[32];
    inet_ntop(AF_INET, &ipheader->m_ulSrcIP, src, sizeof(src));
    inet_ntop(AF_INET, &ipheader->m_ulDestIP, dst, sizeof(dst));
    list << "Internet Protocal version " + QString::number(ipheader->version)<< "Src:"+QString(src) << "Dst"+QString(dst);
    QTreeWidgetItem* item = new QTreeWidgetItem(list);
    ui.treeWidget->addTopLevelItem(item);
    QList<QTreeWidgetItem*>children;

    list.clear();
    list << "Version:" << QString::number(ipheader->version, 2).rightJustified(4, '0') + "...." << QString::number(ipheader->version);
    children.append(new QTreeWidgetItem(list));

    list.clear();
    list << "Header length:" << "...." + QString::number(ipheader->m_HDlen, 2).rightJustified(4, '0') << QString::number(ipheader->m_HDlen*4);
    children.append(new QTreeWidgetItem(list));

    list.clear();
    list << "Tos:" << QString::number(ipheader->m_byTOS, 2).rightJustified(8, '0');
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

    list.clear();
    list << "Source Address:" << src;
    children.append(new QTreeWidgetItem(list));

    list.clear();
    list << "Destination Address" << dst;
    children.append(new QTreeWidgetItem(list));

    item->addChildren(children);
    return ipheader->m_HDlen * 4;
}
void MyWinshark::setinformation(QString type, int number) {
    if (type == "TCP") {
        setEthernet(number);
        unsigned short iphdlen=setIP(number);
        tcp_header* tcp = (tcp_header*)(information[number].constData() + 14 + iphdlen);
        unsigned short srcport = ntohs(tcp->SourPort);
        unsigned short dstport= ntohs(tcp->DestPort);
        QStringList list;
        list << "Transmission Control Protocol " << "Src port:" + QString::number(srcport)<< "Dst port:" + QString::number(dstport);
        QTreeWidgetItem* item = new QTreeWidgetItem(list);
        ui.treeWidget->addTopLevelItem(item);
        QList<QTreeWidgetItem*>children;

        list.clear();
        list << "Source Port:" << QString::number(srcport);
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Dst Port:" << QString::number(dstport);
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Sequence Number" << QString::number(ntohl(tcp->SequNum));
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Ackonwledge Number" << QString::number(ntohl(tcp->AcknowledgeNum));
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Window Size" << QString::number(ntohs(tcp->WindowSize));
        children.append(new QTreeWidgetItem(list));
        
        list.clear();
        unsigned char flags = tcp->flags;
        QString flag;
        if (flags & 0x10) {
            flag += "ACK ";
        }
        if (flags & 0x08) {
            flag += "PSH ";
        }
        if (flags & 0x01) {
            flag += "FIN ";
        }
        if (flags & 0x04) {
            flag += "RST ";
        }
        list << "Flags:" << "0x" + QString::number(flags, 16).rightJustified(3, '0') << flag;
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Checksum" <<"0x"+QString::number(ntohs(tcp->CheckSum), 16).rightJustified(4, '0');
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Urgent Pointer" << QString::number(ntohs(tcp->surgentPointer));
        children.append(new QTreeWidgetItem(list));

        item->addChildren(children);
    }
    if (type == "UDP") {
        setEthernet(number);
        unsigned short iphdlen = setIP(number);
        udp_header* udp = (udp_header*)(information[number].constData() + 14 + iphdlen);
        unsigned short srcport = ntohs(udp->sport);
        unsigned short dstport = ntohs(udp->dport);
        QStringList list;
        list << "User Datagram Protocol" << "Src Port:"+QString::number(srcport) << "Dst Port:"+QString::number(dstport);
        QTreeWidgetItem* item = new QTreeWidgetItem(list);
        ui.treeWidget->addTopLevelItem(item);
        QList<QTreeWidgetItem*>children;

        list.clear();
        list << "Source Port:" << QString::number(srcport);
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Dst Port:" << QString::number(dstport);
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Length:" << "0x" + QString::number(ntohs(udp->datalen));
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Checksum:" <<"0x"+QString::number(ntohs(udp->checksum),16).rightJustified(4,'0');
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Data";
        QTreeWidgetItem* data = new QTreeWidgetItem(list);
        list.clear();
        list << QString::fromUtf8(QByteArray(information[number].constData() + 14 + iphdlen + sizeof(udp_header), information[number].size() - (14 + iphdlen + sizeof(udp_header))).toHex());
        QTreeWidgetItem* content = new QTreeWidgetItem(list);
        content->setToolTip(0, list[0]);
        data->addChild(content);
        children.append(data);

        item->addChildren(children);
    }
    if (type == "ICMP") {
        setEthernet(number);
        unsigned short iphdlen = setIP(number);
        icmphead* icmp = (icmphead*)(information[number].constData() + 14 + iphdlen);
        QStringList list;
        list << "Internet Control Message Protocol";
        QTreeWidgetItem* item = new QTreeWidgetItem(list);
        ui.treeWidget->addTopLevelItem(item);
        QList<QTreeWidgetItem*>children;

        list.clear();
        list << "Type" << QString::number(icmp->m_byType);
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Code" << QString::number(icmp->m_byCode);
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Checksum" <<"0x"+ QString::number(ntohs(icmp->m_usChecksum),16).rightJustified(4,'0');
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Identifier(BE)" << QString::number(icmp->m_usID)<< "0x" + QString::number(icmp->m_usID, 16).rightJustified(4, '0');
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Identifier(LE)" << QString::number(ntohs(icmp->m_usID)) << "0x" + QString::number(ntohs(icmp->m_usID), 16).rightJustified(4, '0');
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "SeqNumber(BE)" << QString::number(icmp->m_usSeq) << "0x" + QString::number(icmp->m_usSeq, 16).rightJustified(4, '0');
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "SeqNumber(LE)" << QString::number(ntohs(icmp->m_usSeq)) << "0x" + QString::number(ntohs(icmp->m_usSeq), 16).rightJustified(4, '0');
        children.append(new QTreeWidgetItem(list));

        list.clear();
        list << "Data";
        QTreeWidgetItem* data = new QTreeWidgetItem(list);
        list.clear();
        list <<QString::fromUtf8(QByteArray(information[number].constData() + 14 + iphdlen + sizeof(icmphead), information[number].size() - (14 + iphdlen + sizeof(icmphead))).toHex());
        QTreeWidgetItem* content = new QTreeWidgetItem(list);
        content->setToolTip(0, list[0]);
        data->addChild(content);
        children.append(data);

        item->addChildren(children);
    }
}
void MyWinshark::setHex(int number) {
    int rowCount = information[number].size() / 16 + (information[number].size() % 16 != 0 ? 1 : 0);
    ui.Hex->setRowCount(rowCount);
    for (int i = 0; i < information[number].size(); ++i) {
        int row = i / 16;
        int col = i % 16 + 1; // +1 因为第一列是行号

        if (col == 1) {
            // 设置行号，格式为四位十六进制数，不足部分用0填充
            QTableWidgetItem* item = new QTableWidgetItem(QString::number(row * 16, 16).rightJustified(4, '0').toUpper());
            ui.Hex->setItem(row, 0, item);
        }

        // 将字节转换为十六进制字符串
        QString hexByte = QString::number(static_cast<unsigned char>(information[number][i]), 16).rightJustified(2, '0').toUpper();
        // 创建表项并填充数据
        QTableWidgetItem* item = new QTableWidgetItem(hexByte);
        ui.Hex->setItem(row, col, item);
        char ch = static_cast<char>(information[number][i]);
        QString asciiChar = (ch >= 32 && ch <= 126) ? QString(ch) : ".";
        ui.Hex->setItem(row, col+17, new QTableWidgetItem(asciiChar));
    }
}
MyWinshark::~MyWinshark()
{
    if (sniffer->isRunning()) {
        emit endSniff();
        sniffer->quit();
        sniffer->wait();
    }
    information.clear();
    delete sniffer;
}
