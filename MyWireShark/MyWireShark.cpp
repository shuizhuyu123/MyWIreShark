#include "MyWireShark.h"


MyWireShark::MyWireShark(QWidget *parent)
    : QWidget(parent)
{
    ui.setupUi(this);
    setSniffer();
    setConnect();
    setWindow();
}

void MyWireShark::setSniffer()
{   
    sniffer = new Sniffer(this);
    adapters = sniffer->findAdapters();
    timer = new QTimer(this);
    connect(this, &MyWireShark::endSniff, sniffer, &Sniffer::endSniff);
}
void MyWireShark::setWindow()
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

    ui.treeWidget->header()->setSectionResizeMode(QHeaderView::ResizeToContents);

    ui.end->setEnabled(false);
}
void MyWireShark::setConnect()
{   
    
    connect(ui.start, &QToolButton::clicked, this, [=](){
        QStringList list = adapters.keys();
        choose = new AdapterChoose(list);
        choose->setChoose(std::bind(&MyWireShark::chooseadapter, this, std::placeholders::_1));
        choose->setConfirm(std::bind(&MyWireShark::startSniffer, this));
        choose->show();
    });
    connect(ui.end, &QToolButton::clicked, this, [=] {
        timer->stop();
        emit endSniff();
        sniffer->quit();
        QMessageBox::StandardButton reply;
        reply = QMessageBox::question(this, "Save File", u8"保存？",
            QMessageBox::Yes | QMessageBox::No);
        if (reply == QMessageBox::Yes) {
            QString filePath = QFileDialog::getSaveFileName(this, tr("保存"), "",
                tr("Text Files (*.txt);;All Files (*)"));
            progressDialog= new QProgressDialog("Saving...", "Cancel", 0, 0,this);
            connect(this, &MyWireShark::progressUpdated, progressDialog, &QProgressDialog::setValue);
            progressDialog->setWindowModality(Qt::WindowModal);
            progressDialog->setAutoClose(true);
            progressDialog->setMaximum(protocols.size());
            progressDialog->setMinimum(0);
            progressDialog->setWindowTitle(u8"保存中");
            progressDialog->setMinimumDuration(0);
            progressDialog->show();
            QtConcurrent::run([=]() {
                save(filePath);
            });
        }
        ui.end->setEnabled(false);
        ui.start->setEnabled(true);
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
        setInformation(number);
        setHex(number);
    });
}
void MyWireShark::setInformation(int number)
{
    QVector<ProtocolItem> topLevelItems = protocols[number].items;
    addProtocolItemsToTreeWidget(ui.treeWidget, topLevelItems);
}
void MyWireShark::addProtocolItemsToTreeWidget(QTreeWidget* treeWidget, const QVector<ProtocolItem>& items, QTreeWidgetItem* parent) {
    for (const auto& item : items) {
        QStringList rowData = item.data;
        QTreeWidgetItem* itemWidget = new QTreeWidgetItem(rowData);
        if (parent) {
            parent->addChild(itemWidget);
        }
        else {
            treeWidget->addTopLevelItem(itemWidget);
        }
        addProtocolItemsToTreeWidget(treeWidget, item.children, itemWidget); 
    }
}
void MyWireShark::setitem(QStringList summary, ProtocolData protocol)
{
    protocols.insert(count, protocol);
    summary.push_front(QString::number(count++));
    this->summary.push_back(summary);
}
void MyWireShark::startSniffer()
{
    protocols.clear();
    ui.tableWidget->clearContents();
    this->count = 0;
    ui.treeWidget->clear();
    ui.Hex->clear();
    ui.start->setEnabled(false);
    sniffer->setAdapter(adapters[adapter]);
    sniffer->start();
    timer->start(1000);
    ui.end->setEnabled(true);
}

void MyWireShark::save(QString filePath)
{   
    QFile file(filePath);
    int currentNumber = 0;
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        QList<int> keys = protocols.keys();
        std::sort(keys.begin(), keys.end());
        for (auto number : keys) {
            out << "number " <<number<<"\n";
            saveProtocolItems(protocols[number].items, out);
            QByteArray array = std::move(protocols[number].content);
            int rowCount = array.size() / 16 + (array.size() % 16 != 0 ? 1 : 0);
            for (int i = 0; i < array.size(); ++i) {
                int col = i % 16 + 1;
                QString hexByte = QString::number(static_cast<unsigned char>(array[i]), 16).rightJustified(2, '0').toUpper();
                out << hexByte << " ";
                if (col == 16) {
                    // 写入ASCII码
                    for (int j = i - 15; j <= i; ++j) {
                        char ch = static_cast<char>(array[j]);
                        QString asciiChar = (ch >= 32 && ch <= 126) ? QString(ch) : ".";
                        out << asciiChar;
                    }
                    out << "\n";
                }
                if (col < 16 && i == array.size() - 1) {
                    QString gap = "     ";
                    out <<gap.repeated(16-col);
                    for (int j = i - (col-1); j <= i; ++j) {
                        char ch = static_cast<char>(array[j]);
                        QString asciiChar = (ch >= 32 && ch <= 126) ? QString(ch) : ".";
                        out << asciiChar;
                    }
                    out << "\n";
                }    
            }
            out << "\n";
            currentNumber++;
            emit progressUpdated(currentNumber);
        }
        file.close();
    }
    else
       QMessageBox::warning(this, "error", u8"保存失败");
}
void MyWireShark::saveProtocolItems(const QVector<ProtocolItem>& items, QTextStream& out, int level /*= 0*/) {
    for (const auto& item : items) {
        out << QString(" ").repeated(level * 2) << item.data.join(" ") << "\n";
            saveProtocolItems(item.children, out, level + 1); 
    }
}
void MyWireShark::setHex(int number) {
    QByteArray array = protocols[number].content;
    int rowCount = array.size() / 16 + (array.size() % 16 != 0 ? 1 : 0);
    ui.Hex->setRowCount(rowCount);
    for (int i = 0; i < array.size(); ++i) {
        int row = i / 16;
        int col = i % 16 + 1; 

        if (col == 1) {
            QTableWidgetItem* item = new QTableWidgetItem(QString::number(row * 16, 16).rightJustified(4, '0').toUpper());
            ui.Hex->setItem(row, 0, item);
        }
        QString hexByte = QString::number(static_cast<unsigned char>(array[i]), 16).rightJustified(2, '0').toUpper();
        QTableWidgetItem* item = new QTableWidgetItem(hexByte);
        ui.Hex->setItem(row, col, item);
        char ch = static_cast<char>(array[i]);
        QString asciiChar = (ch >= 32 && ch <= 126) ? QString(ch) : ".";
        ui.Hex->setItem(row, col + 17, new QTableWidgetItem(asciiChar));
    }
}

MyWireShark::~MyWireShark()
{   

    if (sniffer->isRunning()) {
        emit endSniff();
        sniffer->quit();
        sniffer->wait();
    }
    delete sniffer;
}
