#include "AdapterChoose.h"
#include "MyWireShark.h"
class MyWireShark;
AdapterChoose::AdapterChoose(QStringList adapters,QWidget *parent)
	: QDialog(parent)
{
	ui.setupUi(this);
	this->setModal(true);
	for (auto item : adapters) {
		ui.listWidget->addItem(new QListWidgetItem(item));
	}
	connect(ui.listWidget, &QListWidget::itemClicked, this, [=](QListWidgetItem* item) {
		ischoose = true;
		choose(item->text());
		});
	connect(ui.confirm, &QPushButton::clicked, this, [=]() {
		if (ischoose) {
			confirm();
			this->close();
			this->deleteLater();
		}
		else {
			QMessageBox::warning(this, u8"´íÎó", u8"ÇëÑ¡ÔñÍø¿¨");
		}
		});
	connect(ui.back, &QPushButton::clicked, this,[=]() {
		this->close();
		this->deleteLater();
		});
}

AdapterChoose::~AdapterChoose()
{}
